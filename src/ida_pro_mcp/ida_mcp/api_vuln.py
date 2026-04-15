"""Vulnerability scan orchestration — binary-wide vuln scanning, crypto detection,
attack surface mapping, and mitigation checks.

Provides 7 MCP tools:
- vuln_scan: Binary-wide or scoped vulnerability scan
- vuln_deep: Deep single-finding analysis with dataflow and callers
- vuln_patterns: List registered vulnerability patterns
- vuln_pattern_add: Register a runtime pattern (unsafe)
- crypto_scan: Detect known crypto constants (AES, SHA, MD5, TEA, etc.)
- attack_surface: Map input sources to dangerous sinks
- check_mitigations: Report binary security posture (NX, PIE, canaries, etc.)
"""

from typing import Annotated, NotRequired, TypedDict

import idaapi
import idautils
import ida_funcs
import ida_name
import ida_hexrays
import ida_bytes
import ida_segment
import idc

from .rpc import tool, unsafe
from .sync import idasync, IDAError
from .utils import parse_address
from .api_ctree import (
    get_pattern_registry,
    _load_builtin_patterns,
    match_function,
    PatternConfig,
    CtreeMatchResult,
)
# NOTE: ctree_query is intentionally NOT imported here — it is @tool @idasync
# decorated, so calling it from within another @idasync function would deadlock.


# ============================================================================
# TypedDicts
# ============================================================================


class VulnFinding(TypedDict):
    id: str
    addr: str
    func_name: str
    pattern_name: str
    category: str
    severity: str
    snippet: str
    confidence: NotRequired[str]


class VulnScanResult(TypedDict):
    scanned_functions: int
    total_findings: int
    findings: list[VulnFinding]
    summary: dict
    error: NotRequired[str]


class VulnDeepResult(TypedDict):
    finding: NotRequired[dict]
    ctree_context: NotRequired[list]
    data_source: NotRequired[list]
    callers: NotRequired[list]
    exploitability: str
    recommendation: str
    error: NotRequired[str]


# ============================================================================
# Severity ordering
# ============================================================================

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _sev_key(finding: dict) -> int:
    return _SEV_ORDER.get(finding.get("severity", "low"), 3)


# ============================================================================
# Crypto constant database
# ============================================================================

CRYPTO_CONSTANTS: dict[str, list[dict]] = {
    "aes": [
        {
            "name": "AES S-box",
            "bytes": [
                0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
                0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            ],
            "type": "bytes",
            "min_match": 16,
        }
    ],
    "sha256": [
        {
            "name": "SHA-256 K[0..3]",
            "values": [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5],
            "type": "immediate",
        }
    ],
    "sha1": [
        {
            "name": "SHA-1 H0",
            "values": [0x67452301],
            "type": "immediate",
        }
    ],
    "md5": [
        {
            "name": "MD5 init A",
            "values": [0x67452301],
            "type": "immediate",
        },
        {
            "name": "MD5 T[1]",
            "values": [0xd76aa478],
            "type": "immediate",
        },
    ],
    "tea": [
        {
            "name": "TEA delta",
            "values": [0x9e3779b9],
            "type": "immediate",
        }
    ],
    "crc32": [
        {
            "name": "CRC32 poly",
            "values": [0xedb88320],
            "type": "immediate",
        }
    ],
    "chacha": [
        {
            "name": "ChaCha c0",
            "values": [0x61707865],
            "type": "immediate",
        }
    ],
    "blowfish": [
        {
            "name": "Blowfish P[0]",
            "values": [0x243f6a88],
            "type": "immediate",
        }
    ],
}

# ============================================================================
# Input / sink databases
# ============================================================================

_INPUT_FUNCTIONS: dict[str, list[str]] = {
    "network": ["recv", "recvfrom", "recvmsg", "WSARecv"],
    "file": ["fread", "fgets", "read", "ReadFile"],
    "stdin": ["scanf", "gets", "getchar", "getline"],
    "argv": ["getopt", "getopt_long", "GetCommandLineA"],
    "env": ["getenv", "GetEnvironmentVariableA"],
}

_DANGEROUS_SINKS: dict[str, list[str]] = {
    "memory": ["memcpy", "memmove", "strcpy", "strcat", "sprintf", "gets", "strncpy"],
    "format": ["printf", "fprintf", "sprintf", "snprintf", "syslog"],
    "command": [
        "system", "popen", "execl", "execlp", "execv", "execvp",
        "ShellExecuteA", "WinExec",
    ],
    "file": ["fopen", "open", "CreateFileA"],
}


# ============================================================================
# Internal helpers
# ============================================================================

def _get_all_import_names() -> set[str]:
    """Return the set of all imported function names."""
    names: set[str] = set()
    nimps = idaapi.get_import_module_qty()
    for i in range(nimps):
        def _cb(ea: int, name: str | None, ord_: int) -> bool:
            if name:
                names.add(name)
                # strip leading underscore variants
                stripped = name.lstrip("_")
                if stripped:
                    names.add(stripped)
            return True
        idaapi.enum_import_names(i, _cb)
    return names


def _find_func_ea_by_name(name: str) -> int:
    """Return EA of a named function or BADADDR."""
    ea = idc.get_name_ea_simple(name)
    if ea != idaapi.BADADDR:
        return ea
    # Try with leading underscore
    ea = idc.get_name_ea_simple("_" + name)
    return ea


def _xref_callers(func_ea: int) -> set[int]:
    """Return set of function EAs that call func_ea."""
    callers: set[int] = set()
    for xref in idautils.CodeRefsTo(func_ea, False):
        f = ida_funcs.get_func(xref)
        if f:
            callers.add(f.start_ea)
    return callers


def _decompile_func(func_ea: int):
    """Decompile function at func_ea. Returns cfunc or None."""
    try:
        hf = ida_hexrays.hexrays_failure_t()
        cfunc = ida_hexrays.decompile(func_ea, hf)
        return cfunc
    except Exception:
        return None


# ============================================================================
# Tool 1: vuln_scan
# ============================================================================


@tool
@idasync
def vuln_scan(
    scope: Annotated[
        str,
        "Function address/name to scan, or 'all' to scan every function",
    ] = "all",
    categories: Annotated[
        str,
        "Comma-separated categories: memory,format_string,integer,uaf,"
        "missing_check,command_injection,crypto or 'all'",
    ] = "all",
    severity_min: Annotated[
        str,
        "Minimum severity to include: low|medium|high|critical",
    ] = "low",
    offset: Annotated[int, "Pagination offset"] = 0,
    count: Annotated[int, "Max findings to return"] = 100,
    max_functions: Annotated[int, "Max functions to decompile when scope='all'"] = 500,
) -> VulnScanResult:
    """Binary-wide (or scoped) vulnerability scan using ctree pattern matching.

    Enumerates functions, decompiles each via Hex-Rays, and applies all
    registered vulnerability patterns. Results are sorted by severity and
    paginated.  Use scope= to limit to a single function, categories= to
    filter by type, and severity_min= to suppress low-priority findings.
    """
    _load_builtin_patterns()
    registry = get_pattern_registry()

    # Build category filter
    cat_filter: set[str] | None = None
    if categories and categories.strip().lower() != "all":
        cat_filter = {c.strip().lower() for c in categories.split(",")}

    selected_patterns: list[PatternConfig] = [
        p for p in registry.values()
        if cat_filter is None or p["category"] in cat_filter
    ]

    sev_threshold = _SEV_ORDER.get(severity_min.strip().lower(), 3)

    raw_findings: list[CtreeMatchResult] = []
    scanned = 0
    error_msg: str | None = None

    if scope.strip().lower() == "all":
        func_eas = list(idautils.Functions())[:max_functions]
        for func_ea in func_eas:
            func = ida_funcs.get_func(func_ea)
            if func is None:
                continue
            func_name = ida_name.get_short_name(func.start_ea) or hex(func.start_ea)
            cfunc = _decompile_func(func.start_ea)
            if cfunc is None:
                continue
            scanned += 1
            hits = match_function(cfunc, selected_patterns, func.start_ea, func_name)
            raw_findings.extend(hits)
    else:
        try:
            ea = parse_address(scope)
        except Exception as exc:
            return {
                "scanned_functions": 0,
                "total_findings": 0,
                "findings": [],
                "summary": {},
                "error": str(exc),
            }
        func = ida_funcs.get_func(ea)
        if func is None:
            error_msg = f"No function at {scope}"
        else:
            func_name = ida_name.get_short_name(func.start_ea) or scope
            cfunc = _decompile_func(func.start_ea)
            if cfunc is None:
                error_msg = f"Decompilation failed for {scope}"
            else:
                scanned = 1
                raw_findings = match_function(
                    cfunc, selected_patterns, func.start_ea, func_name
                )

    # Filter by severity threshold.
    # _SEV_ORDER maps critical→0, high→1, medium→2, low→3 (lower = more severe).
    # Keeping findings whose numeric rank is <= threshold means we keep everything
    # at or above the requested minimum severity (e.g. severity_min="high" keeps
    # critical and high, but drops medium and low).
    filtered = [
        f for f in raw_findings
        if _SEV_ORDER.get(f.get("severity", "low"), 3) <= sev_threshold
    ]

    # Sort by severity (critical first)
    filtered.sort(key=_sev_key)

    # Build summary
    by_category: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for f in filtered:
        by_category[f["category"]] = by_category.get(f["category"], 0) + 1
        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1

    # Assign IDs and convert to VulnFinding
    vuln_findings: list[VulnFinding] = []
    for idx, f in enumerate(filtered):
        vf: VulnFinding = {
            "id": f"vuln_{idx:04d}",
            "addr": f["addr"],
            "func_name": f["func_name"],
            "pattern_name": f["pattern_name"],
            "category": f["category"],
            "severity": f["severity"],
            "snippet": f["snippet"],
        }
        if "match_detail" in f:
            vf["confidence"] = f["match_detail"]
        vuln_findings.append(vf)

    page = vuln_findings[offset: offset + count] if count > 0 else vuln_findings[offset:]

    result: VulnScanResult = {
        "scanned_functions": scanned,
        "total_findings": len(filtered),
        "findings": page,
        "summary": {"by_category": by_category, "by_severity": by_severity},
    }
    if error_msg:
        result["error"] = error_msg
    return result


# ============================================================================
# Tool 2: vuln_deep
# ============================================================================


@tool
@idasync
def vuln_deep(
    addr: Annotated[str, "Function address or name to analyse"],
    pattern: Annotated[str, "Pattern name to focus on, or 'all'"] = "all",
    include_dataflow: Annotated[bool, "Include mcode-level data-source tracing"] = True,
    include_callers: Annotated[bool, "Include caller context for the function"] = True,
    max_depth: Annotated[int, "Max call-graph depth for caller tracing"] = 5,
) -> VulnDeepResult:
    """Deep analysis of a single function or finding.

    Combines ctree pattern matching, optional data-flow context, and
    caller enumeration to produce an exploitability estimate and
    concrete remediation recommendation.
    """
    _load_builtin_patterns()
    registry = get_pattern_registry()

    try:
        ea = parse_address(addr)
    except Exception as exc:
        return {
            "exploitability": "unknown",
            "recommendation": "Could not resolve address.",
            "error": str(exc),
        }

    func = ida_funcs.get_func(ea)
    if func is None:
        return {
            "exploitability": "unknown",
            "recommendation": "No function found at address.",
            "error": f"No function at {addr}",
        }

    func_name = ida_name.get_short_name(func.start_ea) or addr

    # Select patterns
    if pattern.strip().lower() == "all":
        selected = list(registry.values())
    else:
        selected = [
            registry[n.strip()]
            for n in pattern.split(",")
            if n.strip() in registry
        ]

    # Run ctree match
    cfunc = _decompile_func(func.start_ea)
    ctree_hits: list[CtreeMatchResult] = []
    if cfunc is not None:
        ctree_hits = match_function(cfunc, selected, func.start_ea, func_name)

    # Build ctree context from match results directly.
    # NOTE: ctree_query is @tool @idasync decorated — calling it from within
    # another @idasync function would deadlock.  We use the match hits already
    # collected above as the ctree context instead.
    ctree_context: list[dict] = [
        {
            "addr": h.get("addr"),
            "func_name": h.get("func_name"),
            "pattern_name": h.get("pattern_name"),
            "snippet": h.get("snippet"),
        }
        for h in ctree_hits
    ]

    # Data-flow: mcode_source is @idasync decorated — calling it from within
    # another @idasync function would deadlock, and its signature requires
    # (func_addr, var) which we don't have here.  Provide a note instead.
    data_source: dict = {
        "origin_type": "not_available",
        "note": (
            "Use mcode_source(func_addr, var) directly for data-flow analysis. "
            "Calling it from within vuln_deep would deadlock due to nested @idasync."
        ),
    }
    if not include_dataflow:
        data_source = {}

    # Callers
    callers: list[dict] = []
    if include_callers:
        try:
            seen: set[int] = set()
            queue = [func.start_ea]
            depth = 0
            while queue and depth < max_depth:
                next_queue: list[int] = []
                for cur_ea in queue:
                    if cur_ea in seen:
                        continue
                    seen.add(cur_ea)
                    for caller_ea in _xref_callers(cur_ea):
                        if caller_ea not in seen:
                            cname = ida_name.get_short_name(caller_ea) or hex(caller_ea)
                            callers.append({"addr": hex(caller_ea), "name": cname, "depth": depth + 1})
                            next_queue.append(caller_ea)
                queue = next_queue
                depth += 1
        except Exception:
            pass

    # Exploitability heuristic
    max_sev = max(
        (_SEV_ORDER.get(h["severity"], 3) for h in ctree_hits),
        default=3,
    )
    exploitability_map = {0: "critical", 1: "high", 2: "medium", 3: "low"}
    exploitability = exploitability_map.get(max_sev, "low")

    # Recommendation
    if not ctree_hits:
        recommendation = "No vulnerability patterns matched. Manual review recommended."
    else:
        cats = {h["category"] for h in ctree_hits}
        recs: list[str] = []
        if "memory" in cats:
            recs.append("Replace unsafe memory functions (strcpy, sprintf) with bounds-checked variants.")
        if "format_string" in cats:
            recs.append("Always pass a string literal as the format argument; never use user-controlled data.")
        if "integer" in cats:
            recs.append("Validate and bound-check size expressions before use in allocation/copy operations.")
        if "uaf" in cats:
            recs.append("Set pointer to NULL immediately after free(); use ownership-tracking patterns.")
        if "missing_check" in cats:
            recs.append("Check return values of all allocation and I/O calls before use.")
        if "command_injection" in cats:
            recs.append("Avoid system()/popen() with non-literal arguments; use execv() with sanitised argv.")
        if "crypto" in cats:
            recs.append("Use strong, well-reviewed crypto primitives; never hard-code key material.")
        recommendation = " ".join(recs) if recs else "Review flagged patterns carefully."

    result: VulnDeepResult = {
        "finding": {
            "addr": hex(func.start_ea),
            "func_name": func_name,
            "matches": ctree_hits,
        },
        "ctree_context": ctree_context,
        "exploitability": exploitability,
        "recommendation": recommendation,
    }
    if include_dataflow and data_source:
        result["data_source"] = data_source  # type: ignore[assignment]
    if callers:
        result["callers"] = callers
    return result


# ============================================================================
# Tool 3: vuln_patterns
# ============================================================================


@tool
@idasync
def vuln_patterns(
    category: Annotated[
        str,
        "Filter by category: memory,format_string,integer,uaf,missing_check,"
        "command_injection,crypto,custom or 'all'",
    ] = "all",
    include_builtin: Annotated[bool, "Include builtin patterns"] = True,
    include_runtime: Annotated[bool, "Include runtime-added patterns"] = True,
) -> list[dict]:
    """List all registered vulnerability patterns.

    Returns every pattern in the registry, optionally filtered by category
    and/or origin (builtin vs runtime-added).
    """
    _load_builtin_patterns()
    registry = get_pattern_registry()

    cat_lower = category.strip().lower()

    result: list[dict] = []
    for p in registry.values():
        if not include_builtin and p.get("is_builtin", False):
            continue
        if not include_runtime and not p.get("is_builtin", False):
            continue
        if cat_lower != "all" and p["category"] != cat_lower:
            continue
        result.append(dict(p))
    return result


# ============================================================================
# Tool 4: vuln_pattern_add  (unsafe)
# ============================================================================


@unsafe
@tool
@idasync
def vuln_pattern_add(
    name: Annotated[str, "Unique pattern name"],
    category: Annotated[
        str,
        "Category: memory|format_string|integer|uaf|missing_check|command_injection|crypto|custom",
    ],
    severity: Annotated[str, "Severity: low|medium|high|critical"],
    targets: Annotated[
        str,
        "Comma-separated list of target function names (e.g. 'my_alloc,my_copy')",
    ],
    check: Annotated[
        str,
        "Check type: arg_size_unbounded|format_user_controlled|return_unchecked|"
        "integer_overflow_risk|use_after_free|double_free|command_injection|custom_call_pattern",
    ],
    arg_index: Annotated[int, "Argument index to inspect (-1 for N/A or all)"] = -1,
    description: Annotated[str, "Human-readable description"] = "",
) -> dict:
    """Register a runtime vulnerability pattern into the pattern registry.

    The new pattern is immediately available to vuln_scan and ctree_match.
    This operation mutates the shared pattern registry and is therefore
    marked unsafe.
    """
    _load_builtin_patterns()
    registry = get_pattern_registry()

    valid_severities = {"low", "medium", "high", "critical"}
    if severity not in valid_severities:
        return {"ok": False, "error": f"Invalid severity {severity!r}; must be one of {sorted(valid_severities)}"}

    valid_checks = {
        "arg_size_unbounded", "format_user_controlled", "return_unchecked",
        "integer_overflow_risk", "use_after_free", "double_free",
        "command_injection", "custom_call_pattern",
    }
    if check not in valid_checks:
        return {"ok": False, "error": f"Unknown check {check!r}; must be one of {sorted(valid_checks)}"}

    target_list = [t.strip() for t in targets.split(",") if t.strip()]
    if not target_list:
        return {"ok": False, "error": "targets must be a non-empty comma-separated list"}

    pattern: PatternConfig = {
        "name": name,
        "category": category,
        "severity": severity,
        "targets": target_list,
        "check": check,
        "arg_index": arg_index,
        "description": description,
        "is_builtin": False,
    }
    registry[name] = pattern
    return {"ok": True, "pattern": dict(pattern)}


# ============================================================================
# Tool 5: crypto_scan
# ============================================================================


@tool
@idasync
def crypto_scan(
    scope: Annotated[
        str,
        "Address/name of a single function to scan, or 'all' for the whole binary",
    ] = "all",
    algorithms: Annotated[
        str,
        "Comma-separated algorithms to look for: aes,sha256,sha1,md5,tea,crc32,chacha,blowfish or 'all'",
    ] = "all",
) -> list[dict]:
    """Detect known cryptographic constants in the binary.

    Searches for well-known crypto algorithm constants (AES S-box bytes,
    SHA-256 round constants, TEA delta, CRC32 polynomial, etc.) using both
    immediate-value scans (idc.find_imm) and byte-sequence searches
    (ida_bytes.bin_search).

    Returns a list of hits with algorithm name, constant name, and address.
    """
    alg_filter: set[str] | None = None
    if algorithms.strip().lower() != "all":
        alg_filter = {a.strip().lower() for a in algorithms.split(",")}

    # Determine search range
    if scope.strip().lower() == "all":
        search_start = idaapi.inf_get_min_ea()
        search_end = idaapi.inf_get_max_ea()
    else:
        try:
            ea = parse_address(scope)
            func = ida_funcs.get_func(ea)
            if func is None:
                return [{"error": f"No function at {scope}"}]
            search_start = func.start_ea
            search_end = func.end_ea
        except Exception as exc:
            return [{"error": str(exc)}]

    results: list[dict] = []

    for alg, constants in CRYPTO_CONSTANTS.items():
        if alg_filter and alg not in alg_filter:
            continue
        for const in constants:
            if const["type"] == "immediate":
                for val in const["values"]:
                    # Search for this immediate value
                    ea = search_start
                    while True:
                        found_ea, _op = idc.find_imm(ea, idc.SEARCH_DOWN | idc.SEARCH_NEXT, val)
                        if found_ea == idaapi.BADADDR or found_ea >= search_end:
                            break
                        func = ida_funcs.get_func(found_ea)
                        func_name = (
                            ida_name.get_short_name(func.start_ea)
                            if func else "<no function>"
                        )
                        results.append({
                            "algorithm": alg,
                            "constant_name": const["name"],
                            "addr": hex(found_ea),
                            "func_addr": hex(func.start_ea) if func else None,
                            "func_name": func_name,
                            "value": hex(val),
                            "match_type": "immediate",
                        })
                        ea = found_ea + 1

            elif const["type"] == "bytes":
                pattern_bytes = bytes(const["bytes"][: const.get("min_match", 8)])
                ea = search_start
                while True:
                    found_ea = ida_bytes.bin_search(
                        ea,
                        search_end,
                        pattern_bytes,
                        None,
                        ida_bytes.BIN_SEARCH_FORWARD,
                        ida_bytes.BIN_SEARCH_NOBREAK | ida_bytes.BIN_SEARCH_NOSHOW,
                    )
                    if found_ea == idaapi.BADADDR or found_ea >= search_end:
                        break
                    func = ida_funcs.get_func(found_ea)
                    func_name = (
                        ida_name.get_short_name(func.start_ea)
                        if func else "<no function>"
                    )
                    results.append({
                        "algorithm": alg,
                        "constant_name": const["name"],
                        "addr": hex(found_ea),
                        "func_addr": hex(func.start_ea) if func else None,
                        "func_name": func_name,
                        "match_type": "byte_sequence",
                        "matched_bytes": len(pattern_bytes),
                    })
                    ea = found_ea + 1

    return results


# ============================================================================
# Tool 6: attack_surface
# ============================================================================


@tool
@idasync
def attack_surface(
    sink_categories: Annotated[
        str,
        "Sink categories to include: memory,format,command,file or 'all'",
    ] = "all",
    max_depth: Annotated[int, "Max call-graph depth for reachability tracing"] = 5,
    offset: Annotated[int, "Pagination offset"] = 0,
    count: Annotated[int, "Max results to return"] = 50,
) -> dict:
    """Map external input sources to dangerous sink functions.

    Identifies which input-receiving functions (recv, fread, scanf, getenv, etc.)
    and dangerous sink functions (memcpy, strcpy, printf, system, etc.) are
    present in the binary via imports and defined functions, then finds
    functions that call both an input source and a dangerous sink within the
    same call graph (shared callers), indicating a potential attack path.
    """
    # Build category filter for sinks
    sink_cat_filter: set[str] | None = None
    if sink_categories.strip().lower() != "all":
        sink_cat_filter = {c.strip().lower() for c in sink_categories.split(",")}

    # Enumerate which input / sink functions are actually present
    all_names_in_binary: set[str] = set()
    for func_ea in idautils.Functions():
        n = ida_name.get_short_name(func_ea)
        if n:
            all_names_in_binary.add(n)
            all_names_in_binary.add(n.lstrip("_"))
    try:
        imported = _get_all_import_names()
        all_names_in_binary.update(imported)
    except Exception:
        pass

    def _present(names: list[str]) -> list[str]:
        found: list[str] = []
        for n in names:
            if n in all_names_in_binary or n.lstrip("_") in all_names_in_binary:
                found.append(n)
        return found

    present_inputs: dict[str, list[str]] = {
        cat: _present(fns) for cat, fns in _INPUT_FUNCTIONS.items()
    }
    present_sinks: dict[str, list[str]] = {}
    for cat, fns in _DANGEROUS_SINKS.items():
        if sink_cat_filter is None or cat in sink_cat_filter:
            present_sinks[cat] = _present(fns)

    # For each present input/sink, get the set of calling functions
    def _callers_of_name(name: str) -> set[int]:
        ea = _find_func_ea_by_name(name)
        if ea == idaapi.BADADDR:
            return set()
        return _xref_callers(ea)

    # Build caller sets
    input_callers: dict[str, set[int]] = {}
    for cat, fns in present_inputs.items():
        for fn in fns:
            callers = _callers_of_name(fn)
            for c in callers:
                input_callers.setdefault(fn, set()).add(c)

    sink_callers: dict[str, set[int]] = {}
    for cat, fns in present_sinks.items():
        for fn in fns:
            callers = _callers_of_name(fn)
            for c in callers:
                sink_callers.setdefault(fn, set()).add(c)

    # Find shared callers (functions that call both an input and a sink)
    paths: list[dict] = []
    for input_fn, i_callers in input_callers.items():
        for sink_fn, s_callers in sink_callers.items():
            shared = i_callers & s_callers
            for shared_ea in shared:
                sname = ida_name.get_short_name(shared_ea) or hex(shared_ea)
                paths.append({
                    "bridge_addr": hex(shared_ea),
                    "bridge_name": sname,
                    "input_func": input_fn,
                    "sink_func": sink_fn,
                    "risk": "high",
                })

    # Deduplicate
    seen_keys: set[tuple] = set()
    unique_paths: list[dict] = []
    for p in paths:
        k = (p["bridge_addr"], p["input_func"], p["sink_func"])
        if k not in seen_keys:
            seen_keys.add(k)
            unique_paths.append(p)

    page = unique_paths[offset: offset + count] if count > 0 else unique_paths[offset:]

    return {
        "present_input_functions": present_inputs,
        "present_sink_functions": present_sinks,
        "attack_paths": page,
        "total_paths": len(unique_paths),
    }


# ============================================================================
# Tool 7: check_mitigations
# ============================================================================


@tool
@idasync
def check_mitigations() -> dict:
    """Report binary security mitigations and hardening posture.

    Checks for:
    - NX (non-executable stack/data segments)
    - PIE (position-independent executable)
    - RELRO / GOT protection indicators
    - Stack canary (__stack_chk_fail import)
    - RWX segments (readable + writable + executable)
    - FORTIFY_SOURCE (__*_chk function imports)

    Returns a structured dict with a mitigations sub-dict and risk_notes list.
    """
    info = idaapi.get_inf_structure()

    # File type string
    try:
        file_type = idaapi.get_file_type_name()
    except Exception:
        file_type = "unknown"

    # Use idaapi.SEGPERM_* constants with getattr fallback for older IDA versions
    SEGPERM_READ = getattr(idaapi, "SEGPERM_READ", 4)
    SEGPERM_WRITE = getattr(idaapi, "SEGPERM_WRITE", 2)
    SEGPERM_EXEC = getattr(idaapi, "SEGPERM_EXEC", 1)

    # --- NX: look for a segment that is writable AND executable ---
    rwx_segments: list[dict] = []
    nx = True
    seg = ida_segment.get_first_seg()
    while seg is not None:
        perm = seg.perm
        R = (perm & SEGPERM_READ) != 0
        W = (perm & SEGPERM_WRITE) != 0
        X = (perm & SEGPERM_EXEC) != 0
        if W and X:
            nx = False
            seg_name = ida_segment.get_segm_name(seg) or "?"
            rwx_segments.append({
                "name": seg_name,
                "start": hex(seg.start_ea),
                "end": hex(seg.end_ea),
                "perm": f"{'r' if R else '-'}{'w' if W else '-'}{'x' if X else '-'}",
            })
        seg = ida_segment.get_next_seg(seg.start_ea)

    # --- PIE: check if base address is 0 (typical for PIE) ---
    try:
        min_ea = idaapi.inf_get_min_ea()
        pie = min_ea < 0x10000  # heuristic: PIE binaries load near 0
    except Exception:
        pie = False

    # --- Stack canary and FORTIFY_SOURCE: scan imports ---
    stack_canary = False
    fortify = False
    nimps = idaapi.get_import_module_qty()
    for i in range(nimps):
        def _scan_cb(ea: int, name: str | None, ord_: int) -> bool:
            nonlocal stack_canary, fortify
            if name:
                if "__stack_chk_fail" in name:
                    stack_canary = True
                # Only match _chk-suffixed names (FORTIFY_SOURCE wrappers)
                if name.endswith("_chk"):
                    fortify = True
            return True
        idaapi.enum_import_names(i, _scan_cb)

    # --- RELRO: inspect .got.plt and .got sections ---
    # full RELRO: .got.plt absent and .got is read-only; or .got.plt is read-only
    # partial RELRO: .got.plt present and writable (lazy binding)
    # none: neither section found, or .got is writable
    got_plt_seg = None
    got_seg = None
    _s = ida_segment.get_first_seg()
    while _s:
        _seg_name = ida_segment.get_segm_name(_s) or ""
        if _seg_name == ".got.plt":
            got_plt_seg = _s
        elif _seg_name == ".got":
            got_seg = _s
        _s = ida_segment.get_next_seg(_s.start_ea)

    if got_plt_seg is not None:
        if got_plt_seg.perm & SEGPERM_WRITE:
            relro = "partial"
        else:
            relro = "full"
    elif got_seg is not None:
        if not (got_seg.perm & SEGPERM_WRITE):
            relro = "full"
        else:
            relro = "none"
    else:
        relro = "none"

    # Risk notes
    risk_notes: list[str] = []
    if not nx:
        risk_notes.append("Binary has RWX segments — shellcode injection may be possible.")
    if not pie:
        risk_notes.append("Binary does not appear to be PIE — absolute addresses aid exploitation.")
    if not stack_canary:
        risk_notes.append("No __stack_chk_fail import found — stack canary protection may be absent.")
    if not fortify:
        risk_notes.append("No FORTIFY_SOURCE (_chk) functions detected.")
    if rwx_segments:
        risk_notes.append(f"{len(rwx_segments)} RWX segment(s) found: " +
                          ", ".join(s["name"] for s in rwx_segments))

    return {
        "file_type": file_type,
        "mitigations": {
            "nx": nx,
            "pie": pie,
            "relro": relro,
            "stack_canary": stack_canary,
            "rwx_segments": rwx_segments,
            "fortify": fortify,
        },
        "risk_notes": risk_notes,
    }
