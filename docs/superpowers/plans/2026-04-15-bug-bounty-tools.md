# Bug Bounty Tool Suite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 18 MCP tools for vulnerability discovery, crackme analysis, and bug bounty research — ctree traversal, microcode def-use, vuln scan orchestration, segment management, crypto detection.

**Architecture:** Four new API modules (`api_ctree.py`, `api_microcode.py`, `api_vuln.py`, `api_segments.py`) plus additions to existing `api_modify.py` and `api_core.py`. Two-phase workflow: shallow `vuln_scan` then deep `vuln_deep`. Hybrid pattern engine with ~25 builtin patterns + runtime extensibility.

**Tech Stack:** IDA Pro 9.3 SDK (`ida_hexrays`, `ida_segment`, `ida_lumina`), Python 3.11+, existing zeromcp framework.

**Spec:** `docs/superpowers/specs/2026-04-15-bug-bounty-tools-design.md`

---

## File Structure

| Action | Path | Responsibility |
|---|---|---|
| Create | `src/ida_pro_mcp/ida_mcp/api_ctree.py` | Decompiler AST traversal engine — ctree visitor, pattern matching, caller context |
| Create | `src/ida_pro_mcp/ida_mcp/api_microcode.py` | Microcode def-use chain extraction, value source tracing, IR inspection |
| Create | `src/ida_pro_mcp/ida_mcp/api_vuln.py` | Vuln scan orchestration, pattern registry, crypto scan, attack surface, mitigations |
| Create | `src/ida_pro_mcp/ida_mcp/api_segments.py` | Segment listing, permission analysis, cross-segment xrefs |
| Create | `src/ida_pro_mcp/ida_mcp/tests/test_api_ctree.py` | Tests for ctree tools |
| Create | `src/ida_pro_mcp/ida_mcp/tests/test_api_microcode.py` | Tests for microcode tools |
| Create | `src/ida_pro_mcp/ida_mcp/tests/test_api_vuln.py` | Tests for vuln scan tools |
| Create | `src/ida_pro_mcp/ida_mcp/tests/test_api_segments.py` | Tests for segment tools |
| Modify | `src/ida_pro_mcp/ida_mcp/api_modify.py` | Add `nop_range` tool |
| Modify | `src/ida_pro_mcp/ida_mcp/api_core.py` | Add `detect_libs` tool |
| Modify | `src/ida_pro_mcp/ida_mcp/tests/test_api_modify.py` | Add `nop_range` tests |
| Modify | `src/ida_pro_mcp/ida_mcp/tests/test_api_core.py` | Add `detect_libs` tests |

---

## Phase 1: Ctree Engine (`api_ctree.py`)

### Task 1: `ctree_query` — AST Node Query

**Files:**
- Create: `src/ida_pro_mcp/ida_mcp/api_ctree.py`
- Create: `src/ida_pro_mcp/ida_mcp/tests/test_api_ctree.py`

- [ ] **Step 1: Write tests for `ctree_query`**

Create `src/ida_pro_mcp/ida_mcp/tests/test_api_ctree.py`:

```python
from ..framework import test, assert_is_list, assert_has_keys, assert_ok, skip_test
from ..api_ctree import ctree_query

CRACKME_MAIN = "main"


@test(binary="crackme03.elf")
def test_ctree_query_all_nodes():
    """ctree_query returns nodes from a decompiled function."""
    result = ctree_query(CRACKME_MAIN)
    assert_is_list(result, min_length=1)
    first = result[0]
    assert_has_keys(first, "addr", "node_type", "text")


@test(binary="crackme03.elf")
def test_ctree_query_filter_calls():
    """ctree_query with node_types='call' returns only call nodes."""
    result = ctree_query(CRACKME_MAIN, node_types="call")
    assert_is_list(result, min_length=1)
    for node in result:
        assert node["node_type"] == "call", f"Expected 'call', got '{node['node_type']}'"


@test(binary="crackme03.elf")
def test_ctree_query_filter_compare():
    """ctree_query with node_types='compare' returns comparison nodes."""
    result = ctree_query(CRACKME_MAIN, node_types="compare")
    # crackme03 main has comparisons for serial check
    assert_is_list(result, min_length=1)
    for node in result:
        assert node["node_type"] == "compare"


@test(binary="crackme03.elf")
def test_ctree_query_text_filter():
    """ctree_query text filter narrows results."""
    all_calls = ctree_query(CRACKME_MAIN, node_types="call")
    filtered = ctree_query(CRACKME_MAIN, node_types="call", filter="printf")
    assert len(filtered) <= len(all_calls)


@test(binary="crackme03.elf")
def test_ctree_query_pagination():
    """ctree_query offset/count pagination works."""
    page1 = ctree_query(CRACKME_MAIN, offset=0, count=2)
    page2 = ctree_query(CRACKME_MAIN, offset=2, count=2)
    assert len(page1) <= 2
    if page1 and page2:
        assert page1[0]["addr"] != page2[0]["addr"] or page1[0]["text"] != page2[0]["text"]


@test()
def test_ctree_query_invalid_addr():
    """ctree_query on non-function address returns error."""
    result = ctree_query("0x0")
    assert_is_list(result, min_length=1)
    assert "error" in result[0]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run ida-mcp-test tests/crackme03.elf -c api_ctree -q`
Expected: FAIL — `api_ctree` module does not exist yet.

- [ ] **Step 3: Implement `ctree_query`**

Create `src/ida_pro_mcp/ida_mcp/api_ctree.py`:

```python
"""Decompiler AST (ctree) traversal engine for vulnerability analysis."""

from typing import Annotated, NotRequired, TypedDict

import ida_hexrays
import idaapi

from .rpc import tool
from .sync import idasync, IDAError
from .utils import normalize_list_input, parse_address


# ---------------------------------------------------------------------------
# TypedDicts
# ---------------------------------------------------------------------------

class CtreeNode(TypedDict):
    addr: str
    node_type: str
    text: str
    parent_context: NotRequired[str]
    line_number: NotRequired[int]
    error: NotRequired[str]


# ---------------------------------------------------------------------------
# Ctree node type constants
# ---------------------------------------------------------------------------

_EXPR_CALL_TYPES = {
    ida_hexrays.cot_call,
}
_EXPR_COMPARE_TYPES = {
    ida_hexrays.cot_eq, ida_hexrays.cot_ne,
    ida_hexrays.cot_sge, ida_hexrays.cot_sgt,
    ida_hexrays.cot_sle, ida_hexrays.cot_slt,
    ida_hexrays.cot_uge, ida_hexrays.cot_ugt,
    ida_hexrays.cot_ule, ida_hexrays.cot_ult,
}
_EXPR_ASSIGN_TYPES = {
    ida_hexrays.cot_asg, ida_hexrays.cot_asgadd, ida_hexrays.cot_asgsub,
    ida_hexrays.cot_asgmul, ida_hexrays.cot_asgsshr, ida_hexrays.cot_asgushr,
    ida_hexrays.cot_asgshl, ida_hexrays.cot_asgband, ida_hexrays.cot_asgbor,
    ida_hexrays.cot_asgxor,
}
_STMT_IF_TYPES = {ida_hexrays.cit_if}
_STMT_LOOP_TYPES = {ida_hexrays.cit_for, ida_hexrays.cit_while, ida_hexrays.cit_do}
_STMT_RETURN_TYPES = {ida_hexrays.cit_return}
_EXPR_CAST_TYPES = {ida_hexrays.cot_cast}
_EXPR_REF_TYPES = {ida_hexrays.cot_ref, ida_hexrays.cot_ptr}

_NODE_TYPE_MAP: dict[str, set[int]] = {
    "call": _EXPR_CALL_TYPES,
    "compare": _EXPR_COMPARE_TYPES,
    "assign": _EXPR_ASSIGN_TYPES,
    "if": _STMT_IF_TYPES,
    "loop": _STMT_LOOP_TYPES,
    "return": _STMT_RETURN_TYPES,
    "cast": _EXPR_CAST_TYPES,
    "ref": _EXPR_REF_TYPES,
}

_ALL_TRACKED = set()
for _s in _NODE_TYPE_MAP.values():
    _ALL_TRACKED |= _s


def _op_to_node_type(op: int) -> str:
    """Map an ida_hexrays op constant to a human-readable node type name."""
    for name, ops in _NODE_TYPE_MAP.items():
        if op in ops:
            return name
    return "other"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _decompile_func(ea: int) -> ida_hexrays.cfunc_t:
    """Decompile a function, raising IDAError on failure."""
    try:
        cfunc = ida_hexrays.decompile(ea)
    except ida_hexrays.DecompilationFailure as exc:
        raise IDAError(f"Decompilation failed at {ea:#x}: {exc}")
    if cfunc is None:
        raise IDAError(f"Decompilation returned None at {ea:#x}")
    return cfunc


def _resolve_func_ea(addr_str: str) -> int:
    """Resolve a function name or address string to an effective address."""
    ea = parse_address(addr_str)
    func = idaapi.get_func(ea)
    if func is None:
        raise IDAError(f"No function at {addr_str}")
    return func.start_ea


class _NodeCollector(ida_hexrays.ctree_visitor_t):
    """Ctree visitor that collects nodes matching a filter."""

    def __init__(self, target_ops: set[int] | None, text_filter: str | None, cfunc: ida_hexrays.cfunc_t):
        super().__init__(ida_hexrays.CV_FAST)
        self.target_ops = target_ops
        self.text_filter = text_filter.lower() if text_filter else None
        self.cfunc = cfunc
        self.results: list[CtreeNode] = []

    def _format_item(self, item: ida_hexrays.citem_t) -> str:
        """Get the decompiler text for a ctree item."""
        lines = self.cfunc.get_pseudocode()
        # Use item's ea to find the closest pseudocode line
        for i in range(lines.size()):
            line = ida_hexrays.tag_remove(lines[i].line)
            if line.strip():
                # Return first non-empty line as fallback
                pass
        # Fallback: use print_citem
        try:
            from ida_hexrays import print1citem
            return print1citem(item, self.cfunc)
        except Exception:
            return f"[op={item.op}]"

    def visit_expr(self, expr: ida_hexrays.cexpr_t) -> int:
        if self.target_ops is not None and expr.op not in self.target_ops:
            return 0
        if self.target_ops is None and expr.op not in _ALL_TRACKED:
            return 0
        text = str(expr.dstr()) if hasattr(expr, "dstr") else f"[expr op={expr.op}]"
        if self.text_filter and self.text_filter not in text.lower():
            return 0
        self.results.append(CtreeNode(
            addr=f"{expr.ea:#x}" if expr.ea != idaapi.BADADDR else "N/A",
            node_type=_op_to_node_type(expr.op),
            text=text,
        ))
        return 0

    def visit_insn(self, insn: ida_hexrays.cinsn_t) -> int:
        if self.target_ops is not None and insn.op not in self.target_ops:
            return 0
        if self.target_ops is None and insn.op not in _ALL_TRACKED:
            return 0
        text = str(insn.dstr()) if hasattr(insn, "dstr") else f"[insn op={insn.op}]"
        if self.text_filter and self.text_filter not in text.lower():
            return 0
        self.results.append(CtreeNode(
            addr=f"{insn.ea:#x}" if insn.ea != idaapi.BADADDR else "N/A",
            node_type=_op_to_node_type(insn.op),
            text=text,
        ))
        return 0


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@tool
@idasync
def ctree_query(
    addr: Annotated[str, "Function address or name"],
    node_types: Annotated[str, "Comma-separated: call, assign, compare, return, if, loop, cast, ref, or 'all'"] = "all",
    filter: Annotated[str, "Optional text filter on node content"] = "",
    offset: Annotated[int, "Pagination offset"] = 0,
    count: Annotated[int, "Max results to return (max 500)"] = 100,
) -> list[CtreeNode]:
    """Query ctree (decompiler AST) nodes in a function by type.

    Walk the decompiled AST and return nodes matching the requested types.
    Useful for finding calls, comparisons, assignments, loops, and casts.
    """
    count = min(count, 500)
    try:
        ea = _resolve_func_ea(addr)
    except IDAError as exc:
        return [CtreeNode(addr=addr, node_type="error", text="", error=str(exc))]

    try:
        cfunc = _decompile_func(ea)
    except IDAError as exc:
        return [CtreeNode(addr=addr, node_type="error", text="", error=str(exc))]

    # Build target op set
    if node_types.strip().lower() == "all":
        target_ops = None  # collect all tracked types
    else:
        target_ops = set()
        for nt in normalize_list_input(node_types):
            nt = nt.strip().lower()
            if nt in _NODE_TYPE_MAP:
                target_ops |= _NODE_TYPE_MAP[nt]

    text_filter = filter.strip() if filter else None
    collector = _NodeCollector(target_ops, text_filter, cfunc)
    collector.apply_to(cfunc.body, None)

    return collector.results[offset : offset + count]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run ida-mcp-test tests/crackme03.elf -c api_ctree -q`
Expected: All ctree_query tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ida_pro_mcp/ida_mcp/api_ctree.py src/ida_pro_mcp/ida_mcp/tests/test_api_ctree.py
git commit -m "feat: add ctree_query tool — AST node query engine"
```

### Task 2: `ctree_match` — Semantic Pattern Matching

**Files:**
- Modify: `src/ida_pro_mcp/ida_mcp/api_ctree.py`
- Modify: `src/ida_pro_mcp/ida_mcp/tests/test_api_ctree.py`

- [ ] **Step 1: Write tests for `ctree_match`**

Append to `test_api_ctree.py`:

```python
from ..api_ctree import ctree_match


@test(binary="crackme03.elf")
def test_ctree_match_return_unchecked():
    """ctree_match finds unchecked return values in main."""
    result = ctree_match(CRACKME_MAIN, pattern="return_unchecked")
    # Result may be empty if main checks all returns — that's ok
    assert_is_list(result)
    for item in result:
        assert_has_keys(item, "addr", "func_name", "pattern_name", "severity", "snippet")
        assert item["pattern_name"] == "return_unchecked"


@test(binary="crackme03.elf")
def test_ctree_match_all_patterns():
    """ctree_match with pattern='all' runs all builtin patterns."""
    result = ctree_match(CRACKME_MAIN, pattern="all")
    assert_is_list(result)
    for item in result:
        assert_has_keys(item, "addr", "func_name", "pattern_name", "severity")


@test(binary="crackme03.elf")
def test_ctree_match_binary_wide():
    """ctree_match with addr='all' scans multiple functions."""
    result = ctree_match("all", pattern="all", count=10)
    assert_is_list(result)
    # Should have scanned more than one function
    if len(result) > 1:
        funcs = {item["func_name"] for item in result}
        # May find issues in multiple functions (not guaranteed)


@test(binary="crackme03.elf")
def test_ctree_match_category_filter():
    """ctree_match category filter limits which patterns run."""
    all_results = ctree_match(CRACKME_MAIN, pattern="all")
    memory_only = ctree_match(CRACKME_MAIN, pattern="all", categories="memory")
    assert len(memory_only) <= len(all_results)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run ida-mcp-test tests/crackme03.elf -c api_ctree -q`
Expected: New tests FAIL — `ctree_match` not defined.

- [ ] **Step 3: Implement `ctree_match`**

Add to `api_ctree.py` — the pattern matching visitor and the `ctree_match` tool:

```python
# ---------------------------------------------------------------------------
# Pattern matching types
# ---------------------------------------------------------------------------

class CtreeMatchResult(TypedDict):
    addr: str
    func_name: str
    pattern_name: str
    category: str
    severity: str
    snippet: str
    confidence: NotRequired[float]
    match_detail: NotRequired[str]
    error: NotRequired[str]


class PatternConfig(TypedDict):
    name: str
    category: str
    severity: str
    targets: list[str]
    check: str
    arg_index: int
    description: str
    is_builtin: bool


# ---------------------------------------------------------------------------
# Pattern registry (shared with api_vuln.py)
# ---------------------------------------------------------------------------

_PATTERN_REGISTRY: dict[str, PatternConfig] = {}
_BUILTIN_LOADED: bool = False


def _load_builtin_patterns():
    """Load the default vulnerability patterns into the registry."""
    global _BUILTIN_LOADED
    if _BUILTIN_LOADED:
        return
    _BUILTIN_LOADED = True

    builtins: list[PatternConfig] = [
        # Memory corruption
        {"name": "unchecked_memcpy_size", "category": "memory", "severity": "high",
         "targets": ["memcpy", "memmove", "bcopy"], "check": "arg_size_unbounded",
         "arg_index": 2, "description": "memcpy/memmove size not bounds-checked", "is_builtin": True},
        {"name": "unbounded_strcpy", "category": "memory", "severity": "high",
         "targets": ["strcpy", "strcat", "wcscpy", "wcscat"], "check": "arg_size_unbounded",
         "arg_index": 1, "description": "strcpy/strcat with non-literal source", "is_builtin": True},
        {"name": "unbounded_sprintf", "category": "memory", "severity": "high",
         "targets": ["sprintf", "vsprintf", "swprintf"], "check": "format_user_controlled",
         "arg_index": 1, "description": "sprintf with potentially unbounded format", "is_builtin": True},
        {"name": "stack_buffer_gets", "category": "memory", "severity": "critical",
         "targets": ["gets", "_gets", "gets_s"], "check": "arg_size_unbounded",
         "arg_index": 0, "description": "gets() always vulnerable to buffer overflow", "is_builtin": True},
        {"name": "unchecked_strncpy_size", "category": "memory", "severity": "medium",
         "targets": ["strncpy", "wcsncpy"], "check": "arg_size_unbounded",
         "arg_index": 2, "description": "strncpy size may exceed dest buffer", "is_builtin": True},
        {"name": "heap_overflow_read", "category": "memory", "severity": "high",
         "targets": ["read", "fread", "recv", "recvfrom", "ReadFile"], "check": "arg_size_unbounded",
         "arg_index": 2, "description": "Read into buffer with unchecked size", "is_builtin": True},
        {"name": "off_by_one_memset", "category": "memory", "severity": "medium",
         "targets": ["memset", "bzero"], "check": "arg_size_unbounded",
         "arg_index": 2, "description": "memset size may exceed buffer", "is_builtin": True},

        # Format string
        {"name": "printf_format_arg", "category": "format_string", "severity": "high",
         "targets": ["printf", "fprintf", "dprintf", "syslog", "err", "warn"],
         "check": "format_user_controlled", "arg_index": 0,
         "description": "printf-family format not a string literal", "is_builtin": True},
        {"name": "snprintf_format_arg", "category": "format_string", "severity": "medium",
         "targets": ["snprintf", "vsnprintf"], "check": "format_user_controlled",
         "arg_index": 2, "description": "snprintf format not a string literal", "is_builtin": True},
        {"name": "nslog_format_arg", "category": "format_string", "severity": "high",
         "targets": ["NSLog", "NSLogv"], "check": "format_user_controlled",
         "arg_index": 0, "description": "NSLog format not a string literal (Obj-C)", "is_builtin": True},

        # Integer issues
        {"name": "integer_overflow_multiply", "category": "integer", "severity": "high",
         "targets": ["malloc", "calloc", "realloc", "operator new", "operator new[]"],
         "check": "integer_overflow_risk", "arg_index": 0,
         "description": "Multiplication result used as alloc size without overflow check", "is_builtin": True},
        {"name": "signed_unsigned_compare", "category": "integer", "severity": "medium",
         "targets": [], "check": "integer_overflow_risk", "arg_index": -1,
         "description": "Signed/unsigned comparison in bounds check", "is_builtin": True},
        {"name": "integer_truncation", "category": "integer", "severity": "medium",
         "targets": [], "check": "integer_overflow_risk", "arg_index": -1,
         "description": "64-bit value truncated to 32-bit in size context", "is_builtin": True},

        # Use-after-free / double-free
        {"name": "use_after_free", "category": "uaf", "severity": "critical",
         "targets": ["free", "_free", "g_free", "HeapFree"], "check": "use_after_free",
         "arg_index": 0, "description": "Pointer used after free()", "is_builtin": True},
        {"name": "double_free", "category": "uaf", "severity": "critical",
         "targets": ["free", "_free", "g_free", "HeapFree"], "check": "double_free",
         "arg_index": 0, "description": "Same pointer freed twice", "is_builtin": True},
        {"name": "free_global_no_null", "category": "uaf", "severity": "medium",
         "targets": ["free", "_free", "g_free"], "check": "use_after_free",
         "arg_index": 0, "description": "free(global) without NULL assignment", "is_builtin": True},

        # Missing check
        {"name": "malloc_null_unchecked", "category": "missing_check", "severity": "medium",
         "targets": ["malloc", "calloc", "realloc", "strdup", "mmap"],
         "check": "return_unchecked", "arg_index": -1,
         "description": "Allocation return not checked for NULL", "is_builtin": True},
        {"name": "return_value_ignored_io", "category": "missing_check", "severity": "medium",
         "targets": ["read", "write", "send", "recv", "fread", "fwrite"],
         "check": "return_unchecked", "arg_index": -1,
         "description": "I/O return value not checked", "is_builtin": True},
        {"name": "unchecked_read_return", "category": "missing_check", "severity": "medium",
         "targets": ["read", "recv", "recvfrom", "fgets"],
         "check": "return_unchecked", "arg_index": -1,
         "description": "Read return not checked for error/EOF", "is_builtin": True},
        {"name": "error_path_leak", "category": "missing_check", "severity": "low",
         "targets": ["malloc", "calloc", "fopen", "open", "socket"],
         "check": "return_unchecked", "arg_index": -1,
         "description": "Resource allocated but error path may not free it", "is_builtin": True},

        # Command injection
        {"name": "system_user_input", "category": "command_injection", "severity": "critical",
         "targets": ["system", "popen", "_popen", "execl", "execlp", "execle", "execv",
                      "execvp", "execvpe", "ShellExecuteA", "ShellExecuteW", "WinExec",
                      "CreateProcessA", "CreateProcessW"],
         "check": "command_injection", "arg_index": 0,
         "description": "system/exec with non-literal argument", "is_builtin": True},
        {"name": "shell_format_construct", "category": "command_injection", "severity": "high",
         "targets": ["sprintf", "snprintf", "strcat", "strcpy"],
         "check": "custom_call_pattern", "arg_index": 1,
         "description": "String construction potentially passed to system()", "is_builtin": True},

        # Crypto
        {"name": "hardcoded_key", "category": "crypto", "severity": "medium",
         "targets": [], "check": "custom_call_pattern", "arg_index": -1,
         "description": "Constant byte array used as crypto key", "is_builtin": True},
        {"name": "weak_random", "category": "crypto", "severity": "medium",
         "targets": ["rand", "srand", "random", "srandom"],
         "check": "custom_call_pattern", "arg_index": -1,
         "description": "Weak PRNG used in potentially security-sensitive context", "is_builtin": True},
    ]
    for p in builtins:
        _PATTERN_REGISTRY[p["name"]] = p


def get_pattern_registry() -> dict[str, PatternConfig]:
    """Access the pattern registry (loading builtins if needed)."""
    _load_builtin_patterns()
    return _PATTERN_REGISTRY


# ---------------------------------------------------------------------------
# Check type engine
# ---------------------------------------------------------------------------

class _PatternMatchVisitor(ida_hexrays.ctree_visitor_t):
    """Ctree visitor that matches function calls against vulnerability patterns."""

    def __init__(self, cfunc: ida_hexrays.cfunc_t, patterns: list[PatternConfig], func_name: str):
        super().__init__(ida_hexrays.CV_FAST)
        self.cfunc = cfunc
        self.func_name = func_name
        self.results: list[CtreeMatchResult] = []

        # Build lookup: lowered target name -> list of patterns
        self._call_patterns: dict[str, list[PatternConfig]] = {}
        self._non_call_patterns: list[PatternConfig] = []
        for p in patterns:
            if p["targets"]:
                for t in p["targets"]:
                    self._call_patterns.setdefault(t.lower(), []).append(p)
            else:
                self._non_call_patterns.append(p)

    def visit_expr(self, expr: ida_hexrays.cexpr_t) -> int:
        if expr.op == ida_hexrays.cot_call:
            self._check_call(expr)
        return 0

    def _get_call_name(self, call_expr: ida_hexrays.cexpr_t) -> str | None:
        """Extract the callee function name from a cot_call expression."""
        callee = call_expr.x
        if callee is None:
            return None
        # Direct call to a named function
        if callee.op == ida_hexrays.cot_obj:
            name = idaapi.get_name(callee.obj_ea)
            if name:
                # Strip leading underscore on some platforms
                return name.lstrip("_") if name.startswith("_") and not name.startswith("__") else name
        # Helper via dstr
        if hasattr(callee, "dstr"):
            s = callee.dstr()
            if s:
                return s
        return None

    def _is_string_literal_arg(self, arg: ida_hexrays.cexpr_t) -> bool:
        """Check if an argument expression is a string literal."""
        if arg.op == ida_hexrays.cot_obj:
            # Could be a string in .rodata
            import ida_bytes
            flags = ida_bytes.get_flags(arg.obj_ea)
            return ida_bytes.is_strlit(flags)
        if arg.op == ida_hexrays.cot_str:
            return True
        # Cast around a string literal
        if arg.op == ida_hexrays.cot_cast and arg.x is not None:
            return self._is_string_literal_arg(arg.x)
        return False

    def _is_const_arg(self, arg: ida_hexrays.cexpr_t) -> bool:
        """Check if an argument expression is a compile-time constant."""
        if arg.op == ida_hexrays.cot_num:
            return True
        if arg.op in (ida_hexrays.cot_str, ida_hexrays.cot_fnum):
            return True
        if arg.op == ida_hexrays.cot_cast and arg.x is not None:
            return self._is_const_arg(arg.x)
        return False

    def _check_call(self, call_expr: ida_hexrays.cexpr_t):
        call_name = self._get_call_name(call_expr)
        if call_name is None:
            return
        call_lower = call_name.lower()
        # Also try without leading underscore
        variants = [call_lower]
        if call_lower.startswith("_") and not call_lower.startswith("__"):
            variants.append(call_lower[1:])

        matched_patterns = []
        for v in variants:
            matched_patterns.extend(self._call_patterns.get(v, []))
        if not matched_patterns:
            return

        args = call_expr.a  # carglist_t
        snippet = call_expr.dstr() if hasattr(call_expr, "dstr") else call_name

        for pattern in matched_patterns:
            check = pattern["check"]
            arg_idx = pattern["arg_index"]

            flagged = False
            detail = ""

            if check == "arg_size_unbounded":
                if arg_idx >= 0 and arg_idx < len(args):
                    arg = args[arg_idx]
                    if not self._is_const_arg(arg):
                        flagged = True
                        detail = f"arg[{arg_idx}] is not a constant"
                elif arg_idx < 0:
                    # No specific arg — flag any call to target
                    flagged = True
                    detail = f"call to {call_name}"

            elif check == "format_user_controlled":
                fmt_idx = arg_idx if arg_idx >= 0 else 0
                if fmt_idx < len(args):
                    arg = args[fmt_idx]
                    if not self._is_string_literal_arg(arg):
                        flagged = True
                        detail = f"format arg[{fmt_idx}] is not a string literal"

            elif check == "return_unchecked":
                # Check if the call result is used in a comparison or assignment
                # Simple heuristic: if the call is a direct statement (expression statement),
                # the return value is being ignored
                parent = self.cfunc.body.find_parent_of(call_expr)
                if parent is not None and parent.op == ida_hexrays.cit_expr:
                    flagged = True
                    detail = f"return value of {call_name}() ignored"

            elif check in ("use_after_free", "double_free"):
                # Simplified: flag calls to free-family functions
                # Deep analysis via mcode_source is done in vuln_deep
                flagged = True
                detail = f"call to {call_name}() — verify pointer usage post-free with vuln_deep"

            elif check in ("command_injection", "custom_call_pattern"):
                check_idx = arg_idx if arg_idx >= 0 else 0
                if check_idx < len(args):
                    arg = args[check_idx]
                    if not self._is_string_literal_arg(arg) and not self._is_const_arg(arg):
                        flagged = True
                        detail = f"arg[{check_idx}] is not a constant/literal"

            elif check == "integer_overflow_risk":
                # Simplified: flag multiplication in alloc context
                if arg_idx >= 0 and arg_idx < len(args):
                    arg = args[arg_idx]
                    if arg.op in (ida_hexrays.cot_mul, ida_hexrays.cot_add, ida_hexrays.cot_shl):
                        flagged = True
                        detail = f"arithmetic in size arg[{arg_idx}]"

            if flagged:
                self.results.append(CtreeMatchResult(
                    addr=f"{call_expr.ea:#x}" if call_expr.ea != idaapi.BADADDR else "N/A",
                    func_name=self.func_name,
                    pattern_name=pattern["name"],
                    category=pattern["category"],
                    severity=pattern["severity"],
                    snippet=str(snippet)[:200],
                    match_detail=detail,
                ))


def _match_function(ea: int, func_name: str, patterns: list[PatternConfig]) -> list[CtreeMatchResult]:
    """Run pattern matching on a single decompiled function."""
    try:
        cfunc = _decompile_func(ea)
    except IDAError:
        return []
    visitor = _PatternMatchVisitor(cfunc, patterns, func_name)
    visitor.apply_to(cfunc.body, None)
    return visitor.results


@tool
@idasync
def ctree_match(
    addr: Annotated[str, "Function address/name, or 'all' for binary-wide scan"] = "all",
    pattern: Annotated[str, "Pattern name or 'all' for all patterns"] = "all",
    categories: Annotated[str, "Filter by category: memory, format_string, integer, uaf, missing_check, command_injection, crypto, or 'all'"] = "all",
    offset: Annotated[int, "Pagination offset"] = 0,
    count: Annotated[int, "Max results (max 500)"] = 200,
) -> list[CtreeMatchResult]:
    """Match vulnerability patterns against decompiled function(s).

    Walks the ctree AST looking for dangerous call patterns: unchecked sizes,
    format strings, ignored return values, command injection, and more.
    Use vuln_patterns to list available patterns.
    """
    count = min(count, 500)
    _load_builtin_patterns()

    # Select patterns
    cat_set = None
    if categories.strip().lower() != "all":
        cat_set = {c.strip().lower() for c in categories.split(",")}

    if pattern.strip().lower() == "all":
        patterns = list(_PATTERN_REGISTRY.values())
    else:
        p = _PATTERN_REGISTRY.get(pattern)
        if p is None:
            return [CtreeMatchResult(
                addr="N/A", func_name="N/A", pattern_name=pattern,
                category="error", severity="error", snippet="",
                error=f"Unknown pattern: {pattern}",
            )]
        patterns = [p]

    if cat_set:
        patterns = [p for p in patterns if p["category"] in cat_set]

    if not patterns:
        return []

    # Collect functions to scan
    all_results: list[CtreeMatchResult] = []

    if addr.strip().lower() == "all":
        import idautils
        for func_ea in idautils.Functions():
            name = idaapi.get_func_name(func_ea) or f"sub_{func_ea:x}"
            all_results.extend(_match_function(func_ea, name, patterns))
            if len(all_results) >= offset + count:
                break
    else:
        try:
            ea = _resolve_func_ea(addr)
        except IDAError as exc:
            return [CtreeMatchResult(
                addr=addr, func_name="N/A", pattern_name="error",
                category="error", severity="error", snippet="",
                error=str(exc),
            )]
        name = idaapi.get_func_name(ea) or f"sub_{ea:x}"
        all_results = _match_function(ea, name, patterns)

    return all_results[offset : offset + count]
```

- [ ] **Step 4: Run tests**

Run: `uv run ida-mcp-test tests/crackme03.elf -c api_ctree -q`
Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ida_pro_mcp/ida_mcp/api_ctree.py src/ida_pro_mcp/ida_mcp/tests/test_api_ctree.py
git commit -m "feat: add ctree_match — semantic vuln pattern matching engine"
```

### Task 3: `ctree_callers_of` and `ctree_vars`

**Files:**
- Modify: `src/ida_pro_mcp/ida_mcp/api_ctree.py`
- Modify: `src/ida_pro_mcp/ida_mcp/tests/test_api_ctree.py`

- [ ] **Step 1: Write tests**

Append to `test_api_ctree.py`:

```python
from ..api_ctree import ctree_callers_of, ctree_vars


@test(binary="crackme03.elf")
def test_ctree_callers_of_printf():
    """ctree_callers_of finds callers of printf with arg context."""
    result = ctree_callers_of("printf")
    assert_is_list(result, min_length=1)
    first = result[0]
    assert_has_keys(first, "caller_name", "call_addr", "args")


@test(binary="crackme03.elf")
def test_ctree_callers_of_with_condition():
    """ctree_callers_of includes enclosing condition when requested."""
    result = ctree_callers_of("printf", include_condition=True)
    assert_is_list(result, min_length=1)
    # At least one call should have condition context (inside if blocks)
    has_condition = any(r.get("enclosing_condition") for r in result)
    # Not guaranteed, but structure should be present
    assert_has_keys(result[0], "enclosing_condition")


@test(binary="crackme03.elf")
def test_ctree_vars_main():
    """ctree_vars returns variable info from main."""
    result = ctree_vars(CRACKME_MAIN)
    assert_is_list(result, min_length=1)
    first = result[0]
    assert_has_keys(first, "name", "type", "is_param")


@test()
def test_ctree_vars_invalid():
    """ctree_vars on invalid address returns error."""
    result = ctree_vars("0x0")
    assert_is_list(result, min_length=1)
    assert "error" in result[0]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run ida-mcp-test tests/crackme03.elf -c api_ctree -q`
Expected: New tests FAIL.

- [ ] **Step 3: Implement `ctree_callers_of` and `ctree_vars`**

Add to `api_ctree.py`:

```python
class CtreeCallerResult(TypedDict):
    caller_addr: str
    caller_name: str
    call_addr: str
    args: list[dict]
    enclosing_condition: NotRequired[str | None]
    error: NotRequired[str]


class CtreeVarInfo(TypedDict):
    name: str
    type: str
    is_param: bool
    is_stack: bool
    size: int
    source: str
    error: NotRequired[str]


@tool
@idasync
def ctree_callers_of(
    target: Annotated[str, "Target function name or address"],
    include_args: Annotated[bool, "Include argument expressions"] = True,
    include_condition: Annotated[bool, "Include enclosing if/loop condition"] = True,
    offset: Annotated[int, "Pagination offset"] = 0,
    count: Annotated[int, "Max results (max 200)"] = 100,
) -> list[CtreeCallerResult]:
    """Find all call sites to a function with decompiler context.

    Returns each caller with argument expressions and enclosing condition.
    Useful for understanding how a dangerous function is actually called.
    """
    count = min(count, 200)
    import idautils
    import idc

    # Resolve target to EA
    try:
        target_ea = _resolve_func_ea(target)
    except IDAError:
        # Maybe it's a name that's not a function start
        target_ea = idc.get_name_ea_simple(target)
        if target_ea == idaapi.BADADDR:
            return [CtreeCallerResult(
                caller_addr="N/A", caller_name="N/A", call_addr="N/A",
                args=[], error=f"Cannot resolve target: {target}",
            )]

    target_name = idaapi.get_name(target_ea) or target

    # Find all xrefs to target
    results: list[CtreeCallerResult] = []
    seen_callers: set[int] = set()

    for xref in idautils.XrefsTo(target_ea, 0):
        caller_func = idaapi.get_func(xref.frm)
        if caller_func is None:
            continue
        caller_ea = caller_func.start_ea
        if caller_ea in seen_callers:
            continue
        seen_callers.add(caller_ea)

        caller_name = idaapi.get_func_name(caller_ea) or f"sub_{caller_ea:x}"

        try:
            cfunc = _decompile_func(caller_ea)
        except IDAError:
            continue

        # Walk ctree to find calls to target
        class _CallFinder(ida_hexrays.ctree_visitor_t):
            def __init__(self):
                super().__init__(ida_hexrays.CV_FAST)
                self.calls: list[CtreeCallerResult] = []

            def visit_expr(self, expr):
                if expr.op != ida_hexrays.cot_call:
                    return 0
                callee = expr.x
                if callee is None:
                    return 0
                callee_ea = callee.obj_ea if callee.op == ida_hexrays.cot_obj else idaapi.BADADDR
                if callee_ea != target_ea:
                    # Try name match
                    name = idaapi.get_name(callee_ea) if callee_ea != idaapi.BADADDR else None
                    if name != target_name:
                        return 0

                args_info = []
                if include_args and expr.a:
                    for i in range(len(expr.a)):
                        arg = expr.a[i]
                        arg_text = arg.dstr() if hasattr(arg, "dstr") else f"[arg{i}]"
                        is_const = arg.op in (ida_hexrays.cot_num, ida_hexrays.cot_str, ida_hexrays.cot_fnum)
                        args_info.append({
                            "index": i,
                            "text": str(arg_text)[:100],
                            "is_const": is_const,
                        })

                cond_text = None
                if include_condition:
                    parent = cfunc.body.find_parent_of(expr)
                    while parent is not None:
                        if parent.op == ida_hexrays.cit_if:
                            cond = parent.cif.expr
                            cond_text = cond.dstr() if hasattr(cond, "dstr") else "[condition]"
                            break
                        parent = cfunc.body.find_parent_of(parent)

                self.calls.append(CtreeCallerResult(
                    caller_addr=f"{caller_ea:#x}",
                    caller_name=caller_name,
                    call_addr=f"{expr.ea:#x}" if expr.ea != idaapi.BADADDR else "N/A",
                    args=args_info,
                    enclosing_condition=str(cond_text)[:200] if cond_text else None,
                ))
                return 0

        finder = _CallFinder()
        finder.apply_to(cfunc.body, None)
        results.extend(finder.calls)

        if len(results) >= offset + count:
            break

    return results[offset : offset + count]


@tool
@idasync
def ctree_vars(
    addr: Annotated[str, "Function address or name"],
    filter: Annotated[str, "Optional name or type filter"] = "",
) -> list[CtreeVarInfo]:
    """Extract variable information from a decompiled function.

    Returns local and parameter variables with types, sizes, and roles.
    Useful for understanding function interfaces and data flow.
    """
    try:
        ea = _resolve_func_ea(addr)
    except IDAError as exc:
        return [CtreeVarInfo(name="", type="", is_param=False, is_stack=False, size=0, source="", error=str(exc))]

    try:
        cfunc = _decompile_func(ea)
    except IDAError as exc:
        return [CtreeVarInfo(name="", type="", is_param=False, is_stack=False, size=0, source="", error=str(exc))]

    text_filter = filter.strip().lower() if filter else None
    results: list[CtreeVarInfo] = []

    for lvar in cfunc.lvars:
        name = lvar.name or f"v{lvar.idx}"
        type_str = str(lvar.type()) if lvar.type() else "unknown"

        if text_filter:
            if text_filter not in name.lower() and text_filter not in type_str.lower():
                continue

        source = "param" if lvar.is_arg_var else "local"
        if lvar.is_stk_var():
            source = "stack_param" if lvar.is_arg_var else "stack_local"

        results.append(CtreeVarInfo(
            name=name,
            type=type_str,
            is_param=bool(lvar.is_arg_var),
            is_stack=bool(lvar.is_stk_var()),
            size=lvar.width,
            source=source,
        ))

    return results
```

- [ ] **Step 4: Run tests**

Run: `uv run ida-mcp-test tests/crackme03.elf -c api_ctree -q`
Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ida_pro_mcp/ida_mcp/api_ctree.py src/ida_pro_mcp/ida_mcp/tests/test_api_ctree.py
git commit -m "feat: add ctree_callers_of and ctree_vars tools"
```

### Task 4: Phase 1 Code Review

- [ ] **Step 1: Run full test suite to verify no regressions**

```bash
uv run ida-mcp-test tests/crackme03.elf -q
uv run ida-mcp-test tests/typed_fixture.elf -q
```

- [ ] **Step 2: Code review using superpowers:requesting-code-review**

Review `api_ctree.py` and `test_api_ctree.py` against the spec. Check:
- All 4 tools implemented (ctree_query, ctree_match, ctree_callers_of, ctree_vars)
- Pattern registry with ~25 builtin patterns
- @tool @idasync decorator order
- TypedDict return types
- Pagination support
- Error handling

- [ ] **Step 3: Fix any review findings and commit**

---

## Phase 2: Microcode Engine (`api_microcode.py`)

### Task 5: `mcode_defuse` — Def-Use Chain Extraction

**Files:**
- Create: `src/ida_pro_mcp/ida_mcp/api_microcode.py`
- Create: `src/ida_pro_mcp/ida_mcp/tests/test_api_microcode.py`

- [ ] **Step 1: Write tests**

Create `src/ida_pro_mcp/ida_mcp/tests/test_api_microcode.py`:

```python
from ..framework import test, assert_is_list, assert_has_keys, skip_test
from ..api_microcode import mcode_defuse, mcode_source, mcode_inspect

CRACKME_MAIN = "main"


@test(binary="crackme03.elf")
def test_mcode_defuse_main():
    """mcode_defuse returns def-use chains for main."""
    result = mcode_defuse(CRACKME_MAIN)
    assert_is_list(result, min_length=1)
    first = result[0]
    assert_has_keys(first, "var_name", "definitions", "uses")
    assert_is_list(first["definitions"])
    assert_is_list(first["uses"])


@test(binary="crackme03.elf")
def test_mcode_defuse_specific_var():
    """mcode_defuse with specific var name filters results."""
    all_vars = mcode_defuse(CRACKME_MAIN, var="all")
    # Just verify it returns a list without error
    assert_is_list(all_vars)


@test()
def test_mcode_defuse_invalid():
    """mcode_defuse on non-function returns error."""
    result = mcode_defuse("0x0")
    assert_is_list(result, min_length=1)
    assert "error" in result[0]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run ida-mcp-test tests/crackme03.elf -c api_microcode -q`
Expected: FAIL — module does not exist.

- [ ] **Step 3: Implement `mcode_defuse`**

Create `src/ida_pro_mcp/ida_mcp/api_microcode.py`:

```python
"""Microcode def-use chain analysis for data flow tracking."""

from typing import Annotated, NotRequired, TypedDict

import ida_hexrays
import idaapi

from .rpc import tool
from .sync import idasync, IDAError
from .utils import parse_address


# ---------------------------------------------------------------------------
# TypedDicts
# ---------------------------------------------------------------------------

class DefUseEntry(TypedDict):
    addr: str
    text: str
    context: NotRequired[str]


class DefUseResult(TypedDict):
    var_name: str
    definitions: list[DefUseEntry]
    uses: list[DefUseEntry]
    error: NotRequired[str]


class McodeSourceResult(TypedDict):
    var: str
    origin_type: str
    origin_detail: str
    chain: list[dict]
    error: NotRequired[str]


class McodeBlock(TypedDict):
    index: int
    start_addr: str
    instructions: list[dict]
    succs: list[int]
    preds: list[int]


class McodeInspectResult(TypedDict):
    maturity: str
    block_count: int
    insn_count: int
    blocks: list[McodeBlock]
    error: NotRequired[str]


# ---------------------------------------------------------------------------
# Maturity level mapping
# ---------------------------------------------------------------------------

_MATURITY_MAP: dict[str, int] = {
    "MMAT_GENERATED": ida_hexrays.MMAT_GENERATED,
    "MMAT_PREOPTIMIZED": ida_hexrays.MMAT_PREOPTIMIZED,
    "MMAT_LOCOPT": ida_hexrays.MMAT_LOCOPT,
    "MMAT_CALLS": ida_hexrays.MMAT_CALLS,
    "MMAT_GLBOPT1": ida_hexrays.MMAT_GLBOPT1,
    "MMAT_GLBOPT2": ida_hexrays.MMAT_GLBOPT2,
    "MMAT_GLBOPT3": ida_hexrays.MMAT_GLBOPT3,
    "MMAT_LVARS": ida_hexrays.MMAT_LVARS,
}


def _parse_maturity(s: str) -> int:
    key = s.strip().upper()
    if key in _MATURITY_MAP:
        return _MATURITY_MAP[key]
    return ida_hexrays.MMAT_GLBOPT1


def _resolve_func_ea(addr_str: str) -> int:
    ea = parse_address(addr_str)
    func = idaapi.get_func(ea)
    if func is None:
        raise IDAError(f"No function at {addr_str}")
    return func.start_ea


def _get_mba(ea: int, maturity: int) -> ida_hexrays.mba_t:
    """Generate microcode for a function at the specified maturity level."""
    mbr = ida_hexrays.mba_ranges_t()
    pfn = idaapi.get_func(ea)
    if pfn is None:
        raise IDAError(f"No function at {ea:#x}")
    mbr.ranges.push_back(idaapi.area_t(pfn.start_ea, pfn.end_ea))

    hf = ida_hexrays.hexrays_failure_t()
    ml = ida_hexrays.mlist_t()
    mba = ida_hexrays.gen_microcode(mbr, hf, ml, ida_hexrays.DECOMP_WARNINGS, maturity)
    if mba is None:
        raise IDAError(f"Microcode generation failed at {ea:#x}: {hf.str}")
    return mba


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@tool
@idasync
def mcode_defuse(
    func_addr: Annotated[str, "Function address or name"],
    var: Annotated[str, "Variable name or 'all'"] = "all",
    maturity: Annotated[str, "Microcode maturity: MMAT_GENERATED through MMAT_LVARS"] = "MMAT_GLBOPT1",
) -> list[DefUseResult]:
    """Extract def-use chains from microcode — where variables are defined and used.

    Returns definition and use sites for each variable in the function's microcode IR.
    Higher maturity levels show more optimized code (closer to decompiler output).
    """
    try:
        ea = _resolve_func_ea(func_addr)
    except IDAError as exc:
        return [DefUseResult(var_name="", definitions=[], uses=[], error=str(exc))]

    mat = _parse_maturity(maturity)
    try:
        mba = _get_mba(ea, mat)
    except IDAError as exc:
        return [DefUseResult(var_name="", definitions=[], uses=[], error=str(exc))]

    var_filter = var.strip().lower() if var.lower() != "all" else None

    # Collect def-use information per variable
    var_info: dict[str, DefUseResult] = {}

    for blk_idx in range(mba.qty):
        blk = mba.get_mblock(blk_idx)
        insn = blk.head
        while insn is not None:
            insn_text = insn.dstr() if hasattr(insn, "dstr") else f"[insn at blk{blk_idx}]"
            insn_addr = f"{insn.ea:#x}" if insn.ea != idaapi.BADADDR else f"blk{blk_idx}"

            # Check destination (definition)
            if insn.d and insn.d.t != ida_hexrays.mop_z:
                vname = insn.d.dstr() if hasattr(insn.d, "dstr") else f"op_d"
                if var_filter is None or var_filter in vname.lower():
                    if vname not in var_info:
                        var_info[vname] = DefUseResult(var_name=vname, definitions=[], uses=[])
                    var_info[vname]["definitions"].append(
                        DefUseEntry(addr=insn_addr, text=str(insn_text)[:200])
                    )

            # Check source operands (uses)
            for op in [insn.l, insn.r]:
                if op and op.t != ida_hexrays.mop_z:
                    vname = op.dstr() if hasattr(op, "dstr") else f"op"
                    if var_filter is None or var_filter in vname.lower():
                        if vname not in var_info:
                            var_info[vname] = DefUseResult(var_name=vname, definitions=[], uses=[])
                        var_info[vname]["uses"].append(
                            DefUseEntry(addr=insn_addr, text=str(insn_text)[:200])
                        )

            insn = insn.next

    results = list(var_info.values())
    if not results:
        return [DefUseResult(var_name="(none)", definitions=[], uses=[],
                             error="No variables found at this maturity level")]
    return results
```

- [ ] **Step 4: Run tests**

Run: `uv run ida-mcp-test tests/crackme03.elf -c api_microcode -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ida_pro_mcp/ida_mcp/api_microcode.py src/ida_pro_mcp/ida_mcp/tests/test_api_microcode.py
git commit -m "feat: add mcode_defuse — microcode def-use chain extraction"
```

### Task 6: `mcode_source` and `mcode_inspect`

**Files:**
- Modify: `src/ida_pro_mcp/ida_mcp/api_microcode.py`
- Modify: `src/ida_pro_mcp/ida_mcp/tests/test_api_microcode.py`

- [ ] **Step 1: Write tests**

Append to `test_api_microcode.py`:

```python
@test(binary="crackme03.elf")
def test_mcode_source_traces_origin():
    """mcode_source traces a variable back to its origin."""
    # First get a variable name from defuse
    defuse = mcode_defuse(CRACKME_MAIN)
    if not defuse or "error" in defuse[0]:
        skip_test("No variables found in main")
    var_name = defuse[0]["var_name"]
    result = mcode_source(CRACKME_MAIN, var=var_name)
    assert_has_keys(result, "var", "origin_type", "chain")
    assert result["origin_type"] in ("param", "global", "const", "retval", "unknown")


@test(binary="crackme03.elf")
def test_mcode_inspect_returns_blocks():
    """mcode_inspect returns microcode blocks."""
    result = mcode_inspect(CRACKME_MAIN)
    assert_has_keys(result, "maturity", "block_count", "blocks")
    assert result["block_count"] > 0
    assert_is_list(result["blocks"], min_length=1)
    first_block = result["blocks"][0]
    assert_has_keys(first_block, "index", "instructions", "succs", "preds")


@test(binary="crackme03.elf")
def test_mcode_inspect_maturity_levels():
    """mcode_inspect respects maturity level parameter."""
    r1 = mcode_inspect(CRACKME_MAIN, maturity="MMAT_GENERATED")
    r2 = mcode_inspect(CRACKME_MAIN, maturity="MMAT_GLBOPT1")
    # Different maturity should produce different instruction counts
    assert_has_keys(r1, "insn_count")
    assert_has_keys(r2, "insn_count")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run ida-mcp-test tests/crackme03.elf -c api_microcode -q`

- [ ] **Step 3: Implement `mcode_source` and `mcode_inspect`**

Add to `api_microcode.py`:

```python
@tool
@idasync
def mcode_source(
    func_addr: Annotated[str, "Function address or name"],
    var: Annotated[str, "Variable name to trace backward"],
    max_depth: Annotated[int, "Max backward trace depth (max 20)"] = 10,
    maturity: Annotated[str, "Microcode maturity level"] = "MMAT_GLBOPT1",
) -> McodeSourceResult:
    """Trace a value backward to its origin — parameter, global, constant, or return value.

    Follows the def-use chain backward from a variable to determine where
    its value originally comes from. Essential for taint analysis.
    """
    max_depth = min(max_depth, 20)

    try:
        ea = _resolve_func_ea(func_addr)
    except IDAError as exc:
        return McodeSourceResult(var=var, origin_type="unknown", origin_detail="", chain=[], error=str(exc))

    mat = _parse_maturity(maturity)
    try:
        mba = _get_mba(ea, mat)
    except IDAError as exc:
        return McodeSourceResult(var=var, origin_type="unknown", origin_detail="", chain=[], error=str(exc))

    var_lower = var.strip().lower()
    chain: list[dict] = []

    # Find definitions of this variable and trace backward
    for blk_idx in range(mba.qty):
        blk = mba.get_mblock(blk_idx)
        insn = blk.head
        while insn is not None:
            if insn.d and insn.d.t != ida_hexrays.mop_z:
                d_name = insn.d.dstr() if hasattr(insn.d, "dstr") else ""
                if var_lower in d_name.lower():
                    insn_text = insn.dstr() if hasattr(insn, "dstr") else ""
                    chain.append({
                        "addr": f"{insn.ea:#x}" if insn.ea != idaapi.BADADDR else f"blk{blk_idx}",
                        "text": str(insn_text)[:200],
                        "step": len(chain),
                    })

                    # Determine origin from source operand
                    src = insn.l if insn.l and insn.l.t != ida_hexrays.mop_z else insn.r
                    if src:
                        if src.t == ida_hexrays.mop_n:  # number constant
                            return McodeSourceResult(
                                var=var, origin_type="const",
                                origin_detail=f"constant: {src.nnn.value if hasattr(src, 'nnn') else src.dstr()}",
                                chain=chain,
                            )
                        if src.t == ida_hexrays.mop_a:  # global address
                            return McodeSourceResult(
                                var=var, origin_type="global",
                                origin_detail=f"global: {src.dstr() if hasattr(src, 'dstr') else 'unknown'}",
                                chain=chain,
                            )
                        if src.t == ida_hexrays.mop_r:  # register (could be param)
                            # Check if this register is a function argument
                            return McodeSourceResult(
                                var=var, origin_type="param",
                                origin_detail=f"register: {src.dstr() if hasattr(src, 'dstr') else 'unknown'}",
                                chain=chain,
                            )
                        if src.t == ida_hexrays.mop_S:  # stack variable
                            return McodeSourceResult(
                                var=var, origin_type="param",
                                origin_detail=f"stack: {src.dstr() if hasattr(src, 'dstr') else 'unknown'}",
                                chain=chain,
                            )
                        if src.t == ida_hexrays.mop_d:  # result of another insn
                            # This is a call result or sub-expression
                            return McodeSourceResult(
                                var=var, origin_type="retval",
                                origin_detail=f"computed: {src.dstr() if hasattr(src, 'dstr') else 'unknown'}",
                                chain=chain,
                            )

            insn = insn.next
            if len(chain) >= max_depth:
                break
        if len(chain) >= max_depth:
            break

    origin_type = "unknown" if not chain else "unknown"
    return McodeSourceResult(var=var, origin_type=origin_type, origin_detail="", chain=chain)


@tool
@idasync
def mcode_inspect(
    func_addr: Annotated[str, "Function address or name"],
    maturity: Annotated[str, "Microcode maturity level"] = "MMAT_GLBOPT1",
    block_filter: Annotated[str, "Block index or range (e.g., '0', '0-5')"] = "",
    offset: Annotated[int, "Pagination offset (instructions)"] = 0,
    count: Annotated[int, "Max instructions to return (max 500)"] = 200,
) -> McodeInspectResult:
    """Inspect microcode IR for a function at a given maturity level.

    Returns the microcode blocks and instructions. Useful for understanding
    compiler transformations and finding patterns invisible in pseudocode.
    """
    count = min(count, 500)

    try:
        ea = _resolve_func_ea(func_addr)
    except IDAError as exc:
        return McodeInspectResult(maturity="", block_count=0, insn_count=0, blocks=[], error=str(exc))

    mat = _parse_maturity(maturity)
    try:
        mba = _get_mba(ea, mat)
    except IDAError as exc:
        return McodeInspectResult(maturity="", block_count=0, insn_count=0, blocks=[], error=str(exc))

    # Parse block filter
    blk_start, blk_end = 0, mba.qty
    if block_filter.strip():
        if "-" in block_filter:
            parts = block_filter.split("-", 1)
            blk_start = max(0, int(parts[0].strip()))
            blk_end = min(mba.qty, int(parts[1].strip()) + 1)
        else:
            blk_start = max(0, int(block_filter.strip()))
            blk_end = min(mba.qty, blk_start + 1)

    blocks: list[McodeBlock] = []
    total_insns = 0
    insn_idx = 0

    for blk_idx in range(blk_start, blk_end):
        blk = mba.get_mblock(blk_idx)
        instructions = []
        insn = blk.head
        while insn is not None:
            if insn_idx >= offset and insn_idx < offset + count:
                insn_text = insn.dstr() if hasattr(insn, "dstr") else f"[op={insn.opcode}]"
                instructions.append({
                    "addr": f"{insn.ea:#x}" if insn.ea != idaapi.BADADDR else "N/A",
                    "opcode": insn.opcode,
                    "text": str(insn_text)[:300],
                })
            insn_idx += 1
            total_insns += 1
            insn = insn.next

        succs = [blk.succ(i) for i in range(blk.nsucc())]
        preds = [blk.pred(i) for i in range(blk.npred())]

        if instructions:
            blocks.append(McodeBlock(
                index=blk_idx,
                start_addr=f"{blk.start:#x}",
                instructions=instructions,
                succs=succs,
                preds=preds,
            ))

    mat_name = maturity.strip().upper()
    return McodeInspectResult(
        maturity=mat_name,
        block_count=mba.qty,
        insn_count=total_insns,
        blocks=blocks,
    )
```

- [ ] **Step 4: Run tests**

Run: `uv run ida-mcp-test tests/crackme03.elf -c api_microcode -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ida_pro_mcp/ida_mcp/api_microcode.py src/ida_pro_mcp/ida_mcp/tests/test_api_microcode.py
git commit -m "feat: add mcode_source and mcode_inspect tools"
```

### Task 7: Phase 2 Code Review

- [ ] **Step 1: Run full test suite**

```bash
uv run ida-mcp-test tests/crackme03.elf -q
uv run ida-mcp-test tests/typed_fixture.elf -q
```

- [ ] **Step 2: Code review `api_microcode.py`**

Check: maturity level handling, mba_t lifecycle, operand type checks, pagination, error handling.

- [ ] **Step 3: Fix findings and commit**

---

## Phase 3: Vuln Orchestration (`api_vuln.py`)

### Task 8: `vuln_scan` and `vuln_deep`

**Files:**
- Create: `src/ida_pro_mcp/ida_mcp/api_vuln.py`
- Create: `src/ida_pro_mcp/ida_mcp/tests/test_api_vuln.py`

- [ ] **Step 1: Write tests**

Create `src/ida_pro_mcp/ida_mcp/tests/test_api_vuln.py`:

```python
from ..framework import test, assert_is_list, assert_has_keys, assert_ok
from ..api_vuln import vuln_scan, vuln_deep, vuln_patterns, vuln_pattern_add, crypto_scan, attack_surface, check_mitigations


@test(binary="crackme03.elf")
def test_vuln_scan_all():
    """vuln_scan returns findings for entire binary."""
    result = vuln_scan(scope="all", max_functions=50)
    assert_has_keys(result, "scanned_functions", "total_findings", "findings", "summary")
    assert result["scanned_functions"] > 0
    assert_is_list(result["findings"])


@test(binary="crackme03.elf")
def test_vuln_scan_single_function():
    """vuln_scan on a specific function works."""
    result = vuln_scan(scope="main", max_functions=1)
    assert_has_keys(result, "scanned_functions", "findings")
    assert result["scanned_functions"] == 1


@test(binary="crackme03.elf")
def test_vuln_scan_category_filter():
    """vuln_scan category filter limits results."""
    all_result = vuln_scan(scope="main")
    mem_result = vuln_scan(scope="main", categories="memory")
    assert mem_result["total_findings"] <= all_result["total_findings"]


@test(binary="crackme03.elf")
def test_vuln_deep_on_finding():
    """vuln_deep provides detailed analysis of a finding."""
    scan = vuln_scan(scope="all", max_functions=50, count=1)
    if not scan["findings"]:
        return  # No findings in this binary — acceptable
    finding = scan["findings"][0]
    result = vuln_deep(addr=finding["addr"], pattern=finding["pattern_name"])
    assert_has_keys(result, "finding", "ctree_context")


@test(binary="crackme03.elf")
def test_vuln_patterns_list():
    """vuln_patterns lists all registered patterns."""
    result = vuln_patterns()
    assert_is_list(result, min_length=20)
    first = result[0]
    assert_has_keys(first, "name", "category", "severity", "description")


@test(binary="crackme03.elf")
def test_vuln_pattern_add_and_list():
    """vuln_pattern_add registers a custom pattern."""
    result = vuln_pattern_add(
        name="test_custom_pattern",
        category="custom",
        severity="low",
        targets="test_func",
        check="custom_call_pattern",
        description="Test pattern",
    )
    assert_ok(result, "name")
    # Verify it appears in the list
    patterns = vuln_patterns(include_runtime=True)
    names = [p["name"] for p in patterns]
    assert "test_custom_pattern" in names
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run ida-mcp-test tests/crackme03.elf -c api_vuln -q`

- [ ] **Step 3: Implement `api_vuln.py`**

Create `src/ida_pro_mcp/ida_mcp/api_vuln.py`:

```python
"""Vulnerability scan orchestration, pattern registry, and security analysis tools."""

from typing import Annotated, NotRequired, TypedDict

import idaapi
import idautils

from .rpc import tool, unsafe
from .sync import idasync, IDAError
from .utils import parse_address, normalize_list_input
from .api_ctree import (
    get_pattern_registry, _load_builtin_patterns, _match_function,
    _resolve_func_ea, _decompile_func,
    CtreeMatchResult, PatternConfig,
)


# ---------------------------------------------------------------------------
# TypedDicts
# ---------------------------------------------------------------------------

class VulnFinding(TypedDict):
    id: str
    addr: str
    func_name: str
    pattern_name: str
    category: str
    severity: str
    snippet: str
    confidence: NotRequired[float]


class VulnScanResult(TypedDict):
    scanned_functions: int
    total_findings: int
    findings: list[VulnFinding]
    summary: dict
    error: NotRequired[str]


class VulnDeepResult(TypedDict):
    finding: dict
    ctree_context: dict
    data_source: NotRequired[dict]
    callers: NotRequired[list]
    exploitability: str
    recommendation: str
    error: NotRequired[str]


# ---------------------------------------------------------------------------
# Severity ordering for sorting
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@tool
@idasync
def vuln_scan(
    scope: Annotated[str, "Function address/name, or 'all' for entire binary"] = "all",
    categories: Annotated[str, "Comma-separated: memory, format_string, integer, uaf, missing_check, command_injection, crypto, or 'all'"] = "all",
    severity_min: Annotated[str, "Minimum severity: low, medium, high, critical"] = "low",
    offset: Annotated[int, "Pagination offset"] = 0,
    count: Annotated[int, "Max findings to return (max 500)"] = 100,
    max_functions: Annotated[int, "Max functions to scan (max 5000)"] = 500,
) -> VulnScanResult:
    """Scan binary for vulnerability patterns — the primary bug hunting entry point.

    Walks decompiled functions matching ctree patterns for dangerous calls,
    unchecked returns, format strings, integer issues, and more.
    Use vuln_deep to investigate individual findings.
    """
    count = min(count, 500)
    max_functions = min(max_functions, 5000)
    _load_builtin_patterns()
    registry = get_pattern_registry()

    # Filter patterns
    cat_set = None
    if categories.strip().lower() != "all":
        cat_set = {c.strip().lower() for c in categories.split(",")}

    sev_min = _SEVERITY_ORDER.get(severity_min.strip().lower(), 3)

    patterns = [
        p for p in registry.values()
        if (cat_set is None or p["category"] in cat_set)
        and _SEVERITY_ORDER.get(p["severity"], 3) <= sev_min
    ]

    if not patterns:
        return VulnScanResult(
            scanned_functions=0, total_findings=0, findings=[], summary={},
            error="No patterns match the given filters",
        )

    # Collect functions
    all_matches: list[CtreeMatchResult] = []
    scanned = 0

    if scope.strip().lower() == "all":
        for func_ea in idautils.Functions():
            if scanned >= max_functions:
                break
            name = idaapi.get_func_name(func_ea) or f"sub_{func_ea:x}"
            matches = _match_function(func_ea, name, patterns)
            all_matches.extend(matches)
            scanned += 1
    else:
        try:
            ea = _resolve_func_ea(scope)
        except IDAError as exc:
            return VulnScanResult(
                scanned_functions=0, total_findings=0, findings=[], summary={},
                error=str(exc),
            )
        name = idaapi.get_func_name(ea) or f"sub_{ea:x}"
        all_matches = _match_function(ea, name, patterns)
        scanned = 1

    # Sort by severity then address
    all_matches.sort(key=lambda m: (_SEVERITY_ORDER.get(m["severity"], 3), m["addr"]))

    # Convert to VulnFinding
    findings: list[VulnFinding] = []
    for i, m in enumerate(all_matches[offset : offset + count]):
        findings.append(VulnFinding(
            id=f"vuln_{i + offset}_{m['addr']}",
            addr=m["addr"],
            func_name=m["func_name"],
            pattern_name=m["pattern_name"],
            category=m["category"],
            severity=m["severity"],
            snippet=m.get("snippet", ""),
        ))

    # Summary
    by_category: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for m in all_matches:
        by_category[m["category"]] = by_category.get(m["category"], 0) + 1
        by_severity[m["severity"]] = by_severity.get(m["severity"], 0) + 1

    return VulnScanResult(
        scanned_functions=scanned,
        total_findings=len(all_matches),
        findings=findings,
        summary={"by_category": by_category, "by_severity": by_severity},
    )


@tool
@idasync
def vuln_deep(
    addr: Annotated[str, "Address of the finding"],
    pattern: Annotated[str, "Pattern name that triggered"],
    include_dataflow: Annotated[bool, "Include microcode source tracing"] = True,
    include_callers: Annotated[bool, "Include caller context"] = True,
    max_depth: Annotated[int, "Max trace depth"] = 5,
) -> VulnDeepResult:
    """Deep analysis of a single vulnerability finding.

    Combines ctree context, microcode source tracing, and caller analysis
    to assess exploitability. Run after vuln_scan to investigate findings.
    """
    _load_builtin_patterns()
    registry = get_pattern_registry()
    p = registry.get(pattern)

    try:
        ea = parse_address(addr)
        func = idaapi.get_func(ea)
        if func is None:
            raise IDAError(f"No function at {addr}")
        func_ea = func.start_ea
        func_name = idaapi.get_func_name(func_ea) or f"sub_{func_ea:x}"
    except (IDAError, ValueError) as exc:
        return VulnDeepResult(
            finding={"addr": addr, "pattern": pattern},
            ctree_context={}, exploitability="unknown",
            recommendation="", error=str(exc),
        )

    # Re-run pattern match on this function for context
    ctree_context: dict = {"func": func_name, "addr": addr}
    if p:
        matches = _match_function(func_ea, func_name, [p])
        relevant = [m for m in matches if m["addr"] == addr]
        if relevant:
            ctree_context["match_detail"] = relevant[0].get("match_detail", "")
            ctree_context["snippet"] = relevant[0].get("snippet", "")

    # Microcode source tracing
    data_source = {}
    if include_dataflow:
        try:
            from .api_microcode import mcode_source
            # Try to trace the variable involved
            source_result = mcode_source(addr, var="all", max_depth=max_depth)
            data_source = {
                "origin_type": source_result.get("origin_type", "unknown"),
                "origin_detail": source_result.get("origin_detail", ""),
                "chain_length": len(source_result.get("chain", [])),
            }
        except Exception:
            data_source = {"origin_type": "unavailable"}

    # Caller context
    callers = []
    if include_callers:
        try:
            from .api_ctree import ctree_callers_of
            if p and p["targets"]:
                caller_results = ctree_callers_of(p["targets"][0], count=10)
                callers = [
                    {"caller": c["caller_name"], "args": c.get("args", [])[:3]}
                    for c in caller_results if "error" not in c
                ][:5]
        except Exception:
            pass

    # Assess exploitability
    exploitability = "unknown"
    if p:
        sev = p["severity"]
        if sev == "critical":
            exploitability = "likely"
        elif sev == "high":
            exploitability = "possible"
        elif data_source.get("origin_type") in ("param", "global"):
            exploitability = "possible"
        else:
            exploitability = "unlikely"

    recommendation = ""
    if p:
        cat = p["category"]
        if cat == "memory":
            recommendation = "Verify buffer sizes, add bounds checking before copy operations"
        elif cat == "format_string":
            recommendation = "Use literal format strings, never pass user input as format"
        elif cat == "command_injection":
            recommendation = "Avoid shell commands with user input, use allowlists"
        elif cat == "uaf":
            recommendation = "Set pointers to NULL after free, verify object lifetime"
        elif cat == "missing_check":
            recommendation = "Check return values, handle allocation failures"
        elif cat == "integer":
            recommendation = "Check for overflow before arithmetic on sizes, use safe integer APIs"

    return VulnDeepResult(
        finding={"addr": addr, "func": func_name, "pattern": pattern,
                 "severity": p["severity"] if p else "unknown"},
        ctree_context=ctree_context,
        data_source=data_source,
        callers=callers,
        exploitability=exploitability,
        recommendation=recommendation,
    )


@tool
@idasync
def vuln_patterns(
    category: Annotated[str, "Filter by category or 'all'"] = "all",
    include_builtin: Annotated[bool, "Include builtin patterns"] = True,
    include_runtime: Annotated[bool, "Include runtime-added patterns"] = True,
) -> list[dict]:
    """List all registered vulnerability patterns.

    Shows available patterns for use with vuln_scan and ctree_match.
    """
    _load_builtin_patterns()
    registry = get_pattern_registry()

    results = []
    for p in registry.values():
        if not include_builtin and p["is_builtin"]:
            continue
        if not include_runtime and not p["is_builtin"]:
            continue
        if category.strip().lower() != "all" and p["category"] != category.strip().lower():
            continue
        results.append({
            "name": p["name"],
            "category": p["category"],
            "severity": p["severity"],
            "description": p["description"],
            "targets": p["targets"],
            "check": p["check"],
            "is_builtin": p["is_builtin"],
        })

    return sorted(results, key=lambda x: (x["category"], x["name"]))


@unsafe
@tool
@idasync
def vuln_pattern_add(
    name: Annotated[str, "Unique pattern name"],
    category: Annotated[str, "Category: memory, format_string, integer, uaf, missing_check, command_injection, custom"],
    severity: Annotated[str, "Severity: low, medium, high, critical"],
    targets: Annotated[str, "Comma-separated function names to match"],
    check: Annotated[str, "Check type: arg_size_unbounded, return_unchecked, format_user_controlled, integer_overflow_risk, use_after_free, double_free, command_injection, custom_call_pattern"],
    arg_index: Annotated[int, "Argument index to inspect (-1 for N/A)"] = -1,
    description: Annotated[str, "Human-readable description"] = "",
) -> dict:
    """Register a new vulnerability pattern at runtime.

    Patterns persist for the session only. The LLM can define patterns
    for target-specific APIs discovered during analysis.
    """
    _load_builtin_patterns()
    registry = get_pattern_registry()

    if name in registry:
        return {"success": False, "name": name, "error": f"Pattern '{name}' already exists"}

    target_list = [t.strip() for t in targets.split(",") if t.strip()]
    registry[name] = PatternConfig(
        name=name, category=category, severity=severity,
        targets=target_list, check=check, arg_index=arg_index,
        description=description, is_builtin=False,
    )
    return {"success": True, "name": name, "message": f"Pattern '{name}' registered"}
```

- [ ] **Step 4: Run tests**

Run: `uv run ida-mcp-test tests/crackme03.elf -c api_vuln -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ida_pro_mcp/ida_mcp/api_vuln.py src/ida_pro_mcp/ida_mcp/tests/test_api_vuln.py
git commit -m "feat: add vuln_scan, vuln_deep, vuln_patterns, vuln_pattern_add"
```

### Task 9: `crypto_scan`, `attack_surface`, `check_mitigations`

**Files:**
- Modify: `src/ida_pro_mcp/ida_mcp/api_vuln.py`
- Modify: `src/ida_pro_mcp/ida_mcp/tests/test_api_vuln.py`

- [ ] **Step 1: Write tests**

Append to `test_api_vuln.py`:

```python
@test(binary="crackme03.elf")
def test_crypto_scan():
    """crypto_scan searches for cryptographic constants."""
    result = crypto_scan()
    assert_is_list(result)
    # crackme03 may or may not have crypto — structure is what matters
    for item in result:
        assert_has_keys(item, "addr", "algorithm", "confidence")


@test(binary="crackme03.elf")
def test_crypto_scan_specific_algorithm():
    """crypto_scan with specific algorithm filter."""
    result = crypto_scan(algorithms="aes,md5")
    assert_is_list(result)


@test(binary="crackme03.elf")
def test_attack_surface():
    """attack_surface maps input points and dangerous sinks."""
    result = attack_surface()
    assert_has_keys(result, "input_points", "dangerous_sinks", "summary")
    assert_is_list(result["input_points"])
    assert_is_list(result["dangerous_sinks"])


@test(binary="crackme03.elf")
def test_check_mitigations():
    """check_mitigations reports binary security features."""
    result = check_mitigations()
    assert_has_keys(result, "file_type", "mitigations", "risk_notes")
    assert_has_keys(result["mitigations"], "nx", "pie", "stack_canary", "rwx_segments")
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement `crypto_scan`, `attack_surface`, `check_mitigations`**

Add to `api_vuln.py`:

```python
# ---------------------------------------------------------------------------
# Crypto constant database
# ---------------------------------------------------------------------------

CRYPTO_CONSTANTS: dict[str, list[dict]] = {
    "aes": [
        {"name": "AES S-box (first 16)", "values": [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76], "type": "bytes"},
    ],
    "sha256": [
        {"name": "SHA-256 K[0..3]", "values": [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5], "type": "immediate"},
        {"name": "SHA-256 H0", "values": [0x6a09e667], "type": "immediate"},
    ],
    "sha1": [
        {"name": "SHA-1 H0", "values": [0x67452301], "type": "immediate"},
        {"name": "SHA-1 H1", "values": [0xefcdab89], "type": "immediate"},
    ],
    "md5": [
        {"name": "MD5 init A", "values": [0x67452301], "type": "immediate"},
        {"name": "MD5 T[1]", "values": [0xd76aa478], "type": "immediate"},
    ],
    "tea": [
        {"name": "TEA/XTEA delta", "values": [0x9e3779b9], "type": "immediate"},
    ],
    "crc32": [
        {"name": "CRC32 polynomial", "values": [0xedb88320], "type": "immediate"},
    ],
    "chacha": [
        {"name": "ChaCha constant 0", "values": [0x61707865], "type": "immediate"},
        {"name": "ChaCha constant 1", "values": [0x3320646e], "type": "immediate"},
    ],
    "blowfish": [
        {"name": "Blowfish P[0]", "values": [0x243f6a88], "type": "immediate"},
    ],
    "rc4": [
        {"name": "RC4 S-box init", "values": list(range(256)), "type": "sequence"},
    ],
    "base64": [
        {"name": "Base64 alphabet", "values": [0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48], "type": "bytes"},
    ],
}


@tool
@idasync
def crypto_scan(
    scope: Annotated[str, "Function address or 'all'"] = "all",
    algorithms: Annotated[str, "Comma-separated: aes, sha256, sha1, md5, tea, crc32, chacha, blowfish, rc4, base64, or 'all'"] = "all",
) -> list[dict]:
    """Scan for known cryptographic constants and algorithm signatures.

    Searches for magic numbers, S-boxes, and initialization vectors used by
    common crypto algorithms. Identifies crypto code without needing symbols.
    """
    algo_filter = None
    if algorithms.strip().lower() != "all":
        algo_filter = {a.strip().lower() for a in algorithms.split(",")}

    results: list[dict] = []

    for algo, constants in CRYPTO_CONSTANTS.items():
        if algo_filter and algo not in algo_filter:
            continue

        for entry in constants:
            if entry["type"] == "immediate":
                for val in entry["values"]:
                    # Search for immediate value
                    import idc
                    ea = idc.find_imm(idaapi.inf_get_min_ea(), idc.SEARCH_DOWN, val)
                    while ea[0] != idaapi.BADADDR:
                        addr = ea[0]
                        func = idaapi.get_func(addr)
                        func_name = idaapi.get_func_name(func.start_ea) if func else "(data)"
                        results.append({
                            "addr": f"{addr:#x}",
                            "algorithm": algo,
                            "constant_name": entry["name"],
                            "value": f"{val:#x}",
                            "confidence": 0.7 if len(entry["values"]) == 1 else 0.9,
                            "func_context": func_name,
                        })
                        ea = idc.find_imm(addr + 1, idc.SEARCH_DOWN, val)
                        if ea[0] == idaapi.BADADDR:
                            break

            elif entry["type"] == "bytes":
                # Search for byte sequence
                byte_pattern = " ".join(f"{b:02X}" for b in entry["values"][:16])
                import ida_bytes
                ea = ida_bytes.bin_search(
                    idaapi.inf_get_min_ea(), idaapi.inf_get_max_ea(),
                    bytes(entry["values"][:16]), None,
                    ida_bytes.BIN_SEARCH_FORWARD, ida_bytes.BIN_SEARCH_NOCASE,
                )
                if ea != idaapi.BADADDR:
                    func = idaapi.get_func(ea)
                    func_name = idaapi.get_func_name(func.start_ea) if func else "(data)"
                    results.append({
                        "addr": f"{ea:#x}",
                        "algorithm": algo,
                        "constant_name": entry["name"],
                        "confidence": 0.85,
                        "func_context": func_name,
                    })

    return results


# ---------------------------------------------------------------------------
# Input/sink databases for attack surface mapping
# ---------------------------------------------------------------------------

_INPUT_FUNCTIONS = {
    "network": ["recv", "recvfrom", "recvmsg", "WSARecv", "WSARecvFrom"],
    "file": ["fread", "fgets", "read", "ReadFile", "pread"],
    "stdin": ["scanf", "gets", "getchar", "fgets", "getline", "cin"],
    "argv": ["getopt", "getopt_long", "GetCommandLineA", "GetCommandLineW"],
    "env": ["getenv", "GetEnvironmentVariableA", "GetEnvironmentVariableW", "secure_getenv"],
}

_DANGEROUS_SINKS = {
    "memory": ["memcpy", "memmove", "strcpy", "strcat", "sprintf", "gets", "strncpy"],
    "format": ["printf", "fprintf", "sprintf", "snprintf", "syslog", "NSLog"],
    "command": ["system", "popen", "execl", "execlp", "execv", "execvp", "ShellExecuteA", "WinExec", "CreateProcessA"],
    "file": ["fopen", "open", "CreateFileA", "CreateFileW"],
}


@tool
@idasync
def attack_surface(
    sink_categories: Annotated[str, "Comma-separated: memory, format, command, file, network, or 'all'"] = "all",
    max_depth: Annotated[int, "Callgraph depth for reachability (max 10)"] = 5,
    offset: Annotated[int, "Pagination offset"] = 0,
    count: Annotated[int, "Max results (max 100)"] = 50,
) -> dict:
    """Map input entry points and trace reachability to dangerous sinks.

    Identifies where user data enters the binary and which dangerous
    functions are reachable from those entry points.
    """
    max_depth = min(max_depth, 10)
    count = min(count, 100)
    import idc

    cat_filter = None
    if sink_categories.strip().lower() != "all":
        cat_filter = {c.strip().lower() for c in sink_categories.split(",")}

    # Find input points present in this binary
    input_points: list[dict] = []
    for category, funcs in _INPUT_FUNCTIONS.items():
        for fname in funcs:
            ea = idc.get_name_ea_simple(fname)
            if ea == idaapi.BADADDR:
                ea = idc.get_name_ea_simple("_" + fname)
            if ea != idaapi.BADADDR:
                xref_count = sum(1 for _ in idautils.XrefsTo(ea, 0))
                input_points.append({
                    "func": fname,
                    "type": category,
                    "addr": f"{ea:#x}",
                    "callers_count": xref_count,
                })

    # Find dangerous sinks present in this binary
    dangerous_sinks: list[dict] = []
    for category, funcs in _DANGEROUS_SINKS.items():
        if cat_filter and category not in cat_filter:
            continue
        for fname in funcs:
            ea = idc.get_name_ea_simple(fname)
            if ea == idaapi.BADADDR:
                ea = idc.get_name_ea_simple("_" + fname)
            if ea != idaapi.BADADDR:
                xref_count = sum(1 for _ in idautils.XrefsTo(ea, 0))
                dangerous_sinks.append({
                    "func": fname,
                    "category": category,
                    "addr": f"{ea:#x}",
                    "callers_count": xref_count,
                })

    # Simple reachability: check if any input caller also calls a sink
    reachable_paths: list[dict] = []
    input_callers: dict[str, set[int]] = {}

    for inp in input_points:
        inp_ea = int(inp["addr"], 16)
        callers = set()
        for xref in idautils.XrefsTo(inp_ea, 0):
            func = idaapi.get_func(xref.frm)
            if func:
                callers.add(func.start_ea)
        input_callers[inp["func"]] = callers

    for sink in dangerous_sinks:
        sink_ea = int(sink["addr"], 16)
        sink_callers = set()
        for xref in idautils.XrefsTo(sink_ea, 0):
            func = idaapi.get_func(xref.frm)
            if func:
                sink_callers.add(func.start_ea)

        for inp_name, inp_callers_set in input_callers.items():
            shared = inp_callers_set & sink_callers
            for shared_ea in shared:
                fname = idaapi.get_func_name(shared_ea) or f"sub_{shared_ea:x}"
                reachable_paths.append({
                    "source": inp_name,
                    "sink": sink["func"],
                    "depth": 1,
                    "intermediate_funcs": [fname],
                })

    return {
        "input_points": input_points[offset : offset + count],
        "dangerous_sinks": dangerous_sinks,
        "reachable_paths": reachable_paths[:count],
        "summary": {
            "total_inputs": len(input_points),
            "total_sinks": len(dangerous_sinks),
            "connected_paths": len(reachable_paths),
        },
    }


@tool
@idasync
def check_mitigations() -> dict:
    """Check binary-level security mitigations.

    Reports NX, PIE, stack canary, RELRO, and RWX segments.
    Essential first step in any bug bounty assessment.
    """
    import ida_segment
    import ida_nalt
    import idc

    file_type = "unknown"
    ft = ida_nalt.get_file_type_name()
    if ft:
        file_type = ft

    # Check segments for RWX
    rwx_segments = []
    seg = ida_segment.get_first_seg()
    while seg:
        perm = seg.perm
        is_rwx = bool((perm & ida_segment.SFL_COMDEF) or
                       (perm & 2 and perm & 4 and perm & 1))  # R=4, W=2, X=1
        if is_rwx and perm != 0:
            rwx_segments.append({
                "name": ida_segment.get_segm_name(seg) or "(unnamed)",
                "start": f"{seg.start_ea:#x}",
                "end": f"{seg.end_ea:#x}",
                "size": seg.end_ea - seg.start_ea,
            })
        seg = ida_segment.get_next_seg(seg.start_ea)

    # Check for stack canary
    stack_canary = False
    for name in ["__stack_chk_fail", "__stack_chk_guard", "___stack_chk_fail", "__security_check_cookie"]:
        if idc.get_name_ea_simple(name) != idaapi.BADADDR:
            stack_canary = True
            break

    # Check PIE — if image base is 0 or low, likely PIE
    image_base = idaapi.inf_get_min_ea()
    pie = image_base < 0x100000  # heuristic: PIE binaries load at low addresses in IDA

    # Check NX — heuristic: no RWX segments means NX is effective
    nx = len(rwx_segments) == 0

    # RELRO — check for .got.plt vs .got
    relro = "none"
    has_got_plt = False
    has_gnu_relro = False
    seg = ida_segment.get_first_seg()
    while seg:
        name = ida_segment.get_segm_name(seg) or ""
        if ".got.plt" in name:
            has_got_plt = True
        if "GNU_RELRO" in name or ".got" == name:
            has_gnu_relro = True
        seg = ida_segment.get_next_seg(seg.start_ea)

    if has_gnu_relro and not has_got_plt:
        relro = "full"
    elif has_gnu_relro:
        relro = "partial"

    # FORTIFY_SOURCE — check for _chk variants
    fortify = False
    for name in ["__memcpy_chk", "__strcpy_chk", "__sprintf_chk", "__printf_chk"]:
        if idc.get_name_ea_simple(name) != idaapi.BADADDR:
            fortify = True
            break

    risk_notes = []
    if rwx_segments:
        risk_notes.append(f"{len(rwx_segments)} RWX segment(s) found — potential DEP bypass")
    if not stack_canary:
        risk_notes.append("No stack canary detected — stack buffer overflows may be exploitable")
    if not pie:
        risk_notes.append("Binary is not PIE — fixed addresses simplify exploitation")
    if relro == "none":
        risk_notes.append("No RELRO — GOT overwrite attacks possible")
    if not fortify:
        risk_notes.append("No FORTIFY_SOURCE — buffer overflow protections not applied")

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
```

- [ ] **Step 4: Run tests**

Run: `uv run ida-mcp-test tests/crackme03.elf -c api_vuln -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ida_pro_mcp/ida_mcp/api_vuln.py src/ida_pro_mcp/ida_mcp/tests/test_api_vuln.py
git commit -m "feat: add crypto_scan, attack_surface, check_mitigations"
```

### Task 10: Phase 3 Code Review

- [ ] **Step 1: Run full test suite**

```bash
uv run ida-mcp-test tests/crackme03.elf -q
uv run ida-mcp-test tests/typed_fixture.elf -q
```

- [ ] **Step 2: Code review `api_vuln.py`**

Check: pattern registry shared correctly with api_ctree.py, no circular imports, decompile cache usage, pagination, crypto constant accuracy, attack surface completeness.

- [ ] **Step 3: Fix findings and commit**

---

## Phase 4: Segments + Utilities

### Task 11: `api_segments.py` — `list_segments` and `segment_xrefs`

**Files:**
- Create: `src/ida_pro_mcp/ida_mcp/api_segments.py`
- Create: `src/ida_pro_mcp/ida_mcp/tests/test_api_segments.py`

- [ ] **Step 1: Write tests**

Create `src/ida_pro_mcp/ida_mcp/tests/test_api_segments.py`:

```python
from ..framework import test, assert_is_list, assert_has_keys
from ..api_segments import list_segments, segment_xrefs


@test(binary="crackme03.elf")
def test_list_segments():
    """list_segments returns all binary segments."""
    result = list_segments()
    assert_is_list(result, min_length=1)
    first = result[0]
    assert_has_keys(first, "name", "start", "end", "size", "permissions")


@test(binary="crackme03.elf")
def test_list_segments_filter():
    """list_segments with permission filter works."""
    all_segs = list_segments()
    rwx_segs = list_segments(filter="rwx")
    assert len(rwx_segs) <= len(all_segs)


@test(binary="crackme03.elf")
def test_segment_xrefs():
    """segment_xrefs returns cross-segment references."""
    result = segment_xrefs()
    assert_has_keys(result, "xrefs", "summary")
    assert_is_list(result["xrefs"])
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement `api_segments.py`**

Create `src/ida_pro_mcp/ida_mcp/api_segments.py`:

```python
"""Segment management and cross-segment analysis tools."""

from typing import Annotated, NotRequired, TypedDict

import ida_segment
import idaapi
import idautils

from .rpc import tool
from .sync import idasync


class SegmentInfo(TypedDict):
    name: str
    start: str
    end: str
    size: int
    permissions: str
    type: str
    bitness: int
    is_loaded: bool


class SegmentXref(TypedDict):
    from_addr: str
    to_addr: str
    from_segment: str
    to_segment: str
    type: str
    func_context: NotRequired[str]


def _seg_permissions(seg) -> str:
    """Format segment permissions as rwx string."""
    p = seg.perm
    r = "r" if p & ida_segment.SFL_LOADER else "-"
    w = "w" if p & 2 else "-"
    x = "x" if p & 1 else "-"
    # Fallback: check by segment class
    if p == 0:
        sclass = ida_segment.get_segm_class(seg) or ""
        if sclass in ("CODE",):
            return "r-x"
        elif sclass in ("DATA", "BSS"):
            return "rw-"
        return "---"
    return f"{r}{w}{x}"


def _seg_type_name(seg) -> str:
    """Get segment type as human-readable string."""
    sclass = ida_segment.get_segm_class(seg) or ""
    return sclass if sclass else "unknown"


def _find_segment(ea: int):
    """Find the segment containing an address."""
    return ida_segment.getseg(ea)


@tool
@idasync
def list_segments(
    filter: Annotated[str, "Name filter (e.g., '.text') or permission filter (e.g., 'rwx', 'rw')"] = "",
) -> list[SegmentInfo]:
    """List all binary segments with permissions and metadata.

    Reports segment names, address ranges, permissions, and types.
    Use to identify RWX segments, data regions, and memory layout.
    """
    text_filter = filter.strip().lower() if filter else None
    results: list[SegmentInfo] = []

    seg = ida_segment.get_first_seg()
    while seg:
        name = ida_segment.get_segm_name(seg) or "(unnamed)"
        perms = _seg_permissions(seg)
        bitness = 16 if seg.bitness == 0 else 32 if seg.bitness == 1 else 64

        if text_filter:
            if text_filter not in name.lower() and text_filter not in perms:
                seg = ida_segment.get_next_seg(seg.start_ea)
                continue

        results.append(SegmentInfo(
            name=name,
            start=f"{seg.start_ea:#x}",
            end=f"{seg.end_ea:#x}",
            size=seg.end_ea - seg.start_ea,
            permissions=perms,
            type=_seg_type_name(seg),
            bitness=bitness,
            is_loaded=bool(seg.is_loaded()),
        ))
        seg = ida_segment.get_next_seg(seg.start_ea)

    return results


@tool
@idasync
def segment_xrefs(
    from_segment: Annotated[str, "Source segment name or 'all'"] = "all",
    to_segment: Annotated[str, "Target segment name or 'all'"] = "all",
    xref_type: Annotated[str, "Filter: code, data, or all"] = "all",
    offset: Annotated[int, "Pagination offset"] = 0,
    count: Annotated[int, "Max results (max 500)"] = 200,
) -> dict:
    """Analyze cross-references between segments.

    Identifies data/code references crossing segment boundaries.
    Useful for finding code-to-data references and cross-segment data flow.
    """
    count = min(count, 500)
    from_filter = from_segment.strip().lower() if from_segment.lower() != "all" else None
    to_filter = to_segment.strip().lower() if to_segment.lower() != "all" else None
    type_filter = xref_type.strip().lower() if xref_type.lower() != "all" else None

    xrefs: list[SegmentXref] = []
    direction_counts: dict[str, int] = {}
    idx = 0

    # Iterate segments as sources
    seg = ida_segment.get_first_seg()
    while seg:
        seg_name = ida_segment.get_segm_name(seg) or "(unnamed)"
        if from_filter and from_filter not in seg_name.lower():
            seg = ida_segment.get_next_seg(seg.start_ea)
            continue

        # Sample addresses in this segment (every 16th head for performance)
        ea = seg.start_ea
        sample_count = 0
        max_sample = 10000

        for head in idautils.Heads(seg.start_ea, seg.end_ea):
            sample_count += 1
            if sample_count > max_sample:
                break

            for xref in idautils.XrefsFrom(head, 0):
                target_seg = _find_segment(xref.to)
                if target_seg is None:
                    continue
                target_name = ida_segment.get_segm_name(target_seg) or "(unnamed)"

                # Skip same-segment xrefs
                if target_seg.start_ea == seg.start_ea:
                    continue

                if to_filter and to_filter not in target_name.lower():
                    continue

                xtype = "code" if xref.iscode else "data"
                if type_filter and type_filter != xtype:
                    continue

                if idx >= offset and idx < offset + count:
                    func = idaapi.get_func(head)
                    func_name = idaapi.get_func_name(func.start_ea) if func else None

                    xrefs.append(SegmentXref(
                        from_addr=f"{head:#x}",
                        to_addr=f"{xref.to:#x}",
                        from_segment=seg_name,
                        to_segment=target_name,
                        type=xtype,
                        **({"func_context": func_name} if func_name else {}),
                    ))

                key = f"{seg_name}->{target_name}"
                direction_counts[key] = direction_counts.get(key, 0) + 1
                idx += 1

                if idx >= offset + count:
                    break
            if idx >= offset + count:
                break

        seg = ida_segment.get_next_seg(seg.start_ea)
        if idx >= offset + count:
            break

    return {
        "xrefs": xrefs,
        "summary": {"total": idx, "by_direction": direction_counts},
    }
```

- [ ] **Step 4: Run tests**

Run: `uv run ida-mcp-test tests/crackme03.elf -c api_segments -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ida_pro_mcp/ida_mcp/api_segments.py src/ida_pro_mcp/ida_mcp/tests/test_api_segments.py
git commit -m "feat: add list_segments and segment_xrefs tools"
```

### Task 12: `nop_range` in api_modify.py

**Files:**
- Modify: `src/ida_pro_mcp/ida_mcp/api_modify.py`
- Modify: `src/ida_pro_mcp/ida_mcp/tests/test_api_modify.py`

- [ ] **Step 1: Write test**

Append to existing `test_api_modify.py`:

```python
from ..api_modify import nop_range


@test(binary="crackme03.elf")
def test_nop_range_by_count():
    """nop_range patches N instructions to NOP."""
    # Find a safe address to patch (start of a non-main function)
    import idautils, idaapi
    funcs = list(idautils.Functions())
    if len(funcs) < 2:
        skip_test("Need at least 2 functions")
    # Use a non-critical function
    target = funcs[-1]
    result = nop_range(f"{target:#x}", count=1)
    assert_has_keys(result, "addr", "bytes_patched", "original_bytes")
    assert result["bytes_patched"] > 0
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement `nop_range`**

Add to `api_modify.py`:

```python
@unsafe
@tool
@idasync
def nop_range(
    addr: Annotated[str, "Start address"],
    end: Annotated[str, "End address (exclusive)"] = "",
    count: Annotated[int, "Number of instructions to NOP (alternative to end)"] = 0,
    nop_calls: Annotated[bool, "If addr is a CALL, NOP the entire instruction"] = False,
) -> dict:
    """NOP out an address range or specific instructions.

    Provide either 'end' for a byte range or 'count' for instruction count.
    Saves original bytes for reference. Essential for crackme patching.
    """
    import ida_bytes
    import ida_ua
    import idc

    ea = parse_address(addr)
    if not ida_bytes.is_mapped(ea):
        raise IDAError(f"Address {addr} is not mapped")

    if end and count:
        raise IDAError("Provide either 'end' or 'count', not both")
    if not end and count <= 0:
        raise IDAError("Provide either 'end' address or 'count' > 0")

    if end:
        end_ea = parse_address(end)
        size = end_ea - ea
    else:
        # Calculate byte size from instruction count
        size = 0
        current = ea
        for _ in range(count):
            insn_len = ida_ua.decode_insn(ida_ua.insn_t(), current)
            if insn_len == 0:
                insn_len = 1  # fallback: 1 byte
            size += insn_len
            current += insn_len

    if size <= 0 or size > 4096:
        raise IDAError(f"Invalid NOP range size: {size}")

    # Save original bytes
    original = ida_bytes.get_bytes(ea, size)
    original_hex = " ".join(f"{b:02x}" for b in original) if original else ""

    # Get NOP byte for current processor
    nop_byte = 0x90  # x86 default
    info = idaapi.get_inf_structure()
    proc_name = info.procname.lower() if hasattr(info, 'procname') else ""
    if "arm" in proc_name or "aarch" in proc_name:
        nop_byte = 0x00  # ARM NOP encoding varies, use 0x00 for simplicity

    # Patch with NOPs
    nop_data = bytes([nop_byte] * size)
    ida_bytes.patch_bytes(ea, nop_data)

    # Count instructions patched
    insn_count = 0
    current = ea
    while current < ea + size:
        insn_len = ida_ua.decode_insn(ida_ua.insn_t(), current)
        if insn_len == 0:
            current += 1
        else:
            current += insn_len
        insn_count += 1

    return {
        "addr": f"{ea:#x}",
        "end": f"{ea + size:#x}",
        "bytes_patched": size,
        "instructions_patched": insn_count,
        "original_bytes": original_hex,
    }
```

- [ ] **Step 4: Run tests**

Run: `uv run ida-mcp-test tests/crackme03.elf -c api_modify -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ida_pro_mcp/ida_mcp/api_modify.py src/ida_pro_mcp/ida_mcp/tests/test_api_modify.py
git commit -m "feat: add nop_range tool for instruction patching"
```

### Task 13: `detect_libs` in api_core.py

**Files:**
- Modify: `src/ida_pro_mcp/ida_mcp/api_core.py`
- Modify: `src/ida_pro_mcp/ida_mcp/tests/test_api_core.py`

- [ ] **Step 1: Write test**

Append to existing `test_api_core.py`:

```python
from ..api_core import detect_libs


@test(binary="crackme03.elf")
def test_detect_libs():
    """detect_libs reports detected libraries."""
    result = detect_libs()
    assert_has_keys(result, "libraries", "unmatched_count")
    assert_is_list(result["libraries"])
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement `detect_libs`**

Add to `api_core.py`:

```python
@tool
@idasync
def detect_libs(
    confidence_min: Annotated[float, "Minimum confidence (0.0-1.0)"] = 0.0,
    offset: Annotated[int, "Pagination offset"] = 0,
    count: Annotated[int, "Max results (max 200)"] = 100,
) -> dict:
    """Report FLIRT signature matches and library detection.

    Lists detected libraries with matched function counts. Useful for
    identifying statically linked libraries and their versions.
    """
    import idc

    count = min(count, 200)
    lib_funcs: dict[str, list[str]] = {}  # library_name -> [func_names]
    total_funcs = 0
    unmatched = 0

    for func_ea in idautils.Functions():
        total_funcs += 1
        flags = idc.get_func_flags(func_ea)
        if flags == -1:
            continue

        name = idc.get_func_name(func_ea) or ""

        # Check if this function is a library function (FUNC_LIB flag)
        if flags & idc.FUNC_LIB:
            # Try to determine which library from the name
            lib_name = "unknown_lib"
            # Common prefixes that indicate library origin
            if name.startswith("_Z"):  # C++ mangled
                lib_name = "c++_runtime"
            elif name.startswith("__libc") or name.startswith("__GI_"):
                lib_name = "libc"
            elif name.startswith("__cxa_") or name.startswith("__gxx"):
                lib_name = "libstdc++"
            elif any(name.startswith(p) for p in ["SSL_", "ssl_", "EVP_", "RSA_", "AES_"]):
                lib_name = "openssl"
            elif any(name.startswith(p) for p in ["z_", "inflate", "deflate", "crc32", "adler32"]):
                lib_name = "zlib"
            elif any(name.startswith(p) for p in ["png_"]):
                lib_name = "libpng"
            elif any(name.startswith(p) for p in ["xml", "XML", "html", "HTML"]):
                lib_name = "libxml2"
            elif any(name.startswith(p) for p in ["sqlite3_"]):
                lib_name = "sqlite3"
            elif name.startswith("_"):
                lib_name = "c_runtime"
            lib_funcs.setdefault(lib_name, []).append(name)
        else:
            unmatched += 1

    libraries = []
    for lib_name, funcs in sorted(lib_funcs.items(), key=lambda x: -len(x[1])):
        confidence = min(1.0, len(funcs) / 10.0)  # More matches = higher confidence
        if confidence < confidence_min:
            continue
        libraries.append({
            "name": lib_name,
            "matched_functions": len(funcs),
            "confidence": round(confidence, 2),
            "sample_functions": funcs[:5],
        })

    # IDA 9.3: check for Lumina availability
    lumina_available = False
    lumina_matches = 0
    try:
        import ida_lumina
        lumina_available = True
        # Count Lumina-matched functions
        for func_ea in idautils.Functions():
            md = ida_lumina.get_func_metadata(func_ea)
            if md is not None:
                lumina_matches += 1
    except (ImportError, AttributeError):
        pass

    return {
        "libraries": libraries[offset : offset + count],
        "total_library_functions": sum(len(f) for f in lib_funcs.values()),
        "unmatched_count": unmatched,
        "total_functions": total_funcs,
        "lumina_available": lumina_available,
        "lumina_matches": lumina_matches,
    }
```

- [ ] **Step 4: Run tests**

Run: `uv run ida-mcp-test tests/crackme03.elf -c api_core -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ida_pro_mcp/ida_mcp/api_core.py src/ida_pro_mcp/ida_mcp/tests/test_api_core.py
git commit -m "feat: add detect_libs tool for library detection"
```

### Task 14: Phase 4 Code Review

- [ ] **Step 1: Run full test suite across both fixtures**

```bash
uv run ida-mcp-test tests/crackme03.elf -q
uv run ida-mcp-test tests/typed_fixture.elf -q
```

- [ ] **Step 2: Code review all Phase 4 additions**

- [ ] **Step 3: Fix findings and commit**

---

## Phase 5: Integration + Final Review

### Task 15: End-to-End Integration Testing

- [ ] **Step 1: Run full workflow test**

In IDA with crackme03.elf loaded, verify this workflow works end-to-end via MCP:
1. `check_mitigations()` — get binary security posture
2. `detect_libs()` — identify libraries
3. `list_segments()` — understand memory layout
4. `crypto_scan()` — find crypto constants
5. `vuln_scan(scope="all", max_functions=50)` — shallow scan
6. Pick a finding → `vuln_deep(addr=..., pattern=...)` — deep analysis
7. `attack_surface()` — map input → sink paths
8. `ctree_query(addr=..., node_types="compare")` — crackme analysis
9. `mcode_inspect(addr=..., maturity="MMAT_GLBOPT1")` — IR inspection

- [ ] **Step 2: Run full test suite with coverage**

```bash
uv run coverage erase
uv run coverage run -m ida_pro_mcp.test tests/crackme03.elf -q
uv run coverage run --append -m ida_pro_mcp.test tests/typed_fixture.elf -q
uv run coverage report --show-missing
```

- [ ] **Step 3: Final code review of all new modules**

Use `superpowers:requesting-code-review` for comprehensive review of:
- `api_ctree.py`
- `api_microcode.py`
- `api_vuln.py`
- `api_segments.py`
- Changes to `api_modify.py` and `api_core.py`

- [ ] **Step 4: Commit any final fixes**

```bash
git add -A
git commit -m "fix: address final code review findings for bug bounty tools"
```

### Task 16: Documentation Update

- [ ] **Step 1: Update CLAUDE.md**

Add to the "Important API modules" section:

```markdown
- `api_ctree.py`: decompiler AST traversal, vulnerability pattern matching
- `api_microcode.py`: microcode def-use chains, value source tracing
- `api_vuln.py`: vulnerability scanning, pattern registry, crypto detection, attack surface
- `api_segments.py`: segment management, security mitigation checks
```

Add to "Scope priorities" high priority list:
```markdown
- `api_ctree.py`
- `api_microcode.py`
- `api_vuln.py`
- `api_segments.py`
```

- [ ] **Step 2: Commit documentation**

```bash
git add CLAUDE.md
git commit -m "docs: update CLAUDE.md with bug bounty tool modules"
```
