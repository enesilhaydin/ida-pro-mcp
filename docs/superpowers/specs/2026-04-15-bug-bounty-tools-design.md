# Bug Bounty Tool Suite — Design Spec

**Date:** 2026-04-15
**Status:** Approved
**IDA Version:** 9.3+

## Overview

Extend ida-pro-mcp with 18 new MCP tools focused on vulnerability discovery, crackme analysis, and bug bounty research. Platform-agnostic design supporting Windows PE, Linux ELF, macOS Mach-O, firmware, and bare-metal binaries.

## Architecture

Layered module approach with 4 new files + 2 extensions to existing files:

```
api_ctree.py        → Decompiler AST traversal engine (4 tools)
api_microcode.py    → Microcode def-use chain analysis (3 tools)
api_vuln.py         → Vuln scan orchestration + pattern registry (7 tools)
api_segments.py     → Segment management + security checks (2 tools)
api_modify.py       → +1 tool (nop_range)
api_core.py         → +1 tool (detect_libs)
```

All tools follow existing conventions: `@tool @idasync`, type hints with `Annotated[...]`, batch-first APIs, pagination via `offset/count`.

## Tool Inventory

### api_ctree.py — Decompiler AST Engine

#### `ctree_query`
Query ctree nodes in a decompiled function by node type.

```
ctree_query(
    addr: "Function address or name",
    node_types: "call, assign, compare, return, if, loop, cast, ref" = "all",
    filter: "Optional text filter on node content",
    offset: int = 0,
    count: int = 100
) -> list[dict]
```

Returns: `[{addr, node_type, text, parent_context, line_number}, ...]`

Uses `ida_hexrays.cfunc_t` + `ctree_visitor_t` to walk the AST. Each node includes its decompiler text representation and parent statement context.

#### `ctree_match`
Semantic pattern matching against ctree — the core vuln detection primitive.

```
ctree_match(
    addr: "Function address or name, or 'all' for binary-wide",
    pattern: "Pattern name from registry (e.g., 'unchecked_memcpy_size')",
    categories: "Filter by category: memory, format_string, integer, uaf, missing_check, command_injection" = "all",
    offset: int = 0,
    count: int = 200
) -> list[dict]
```

Returns: `[{addr, func_name, pattern_name, severity, match_detail, snippet, line_number}, ...]`

When `addr="all"`, iterates functions with decompile + visitor. Internally uses the PatternRegistry from `api_vuln.py`.

#### `ctree_callers_of`
Find all call sites to a function with full ctree context.

```
ctree_callers_of(
    target: "Target function name or address",
    include_args: bool = True,
    include_condition: bool = True,
    offset: int = 0,
    count: int = 100
) -> list[dict]
```

Returns: `[{caller_addr, caller_name, call_addr, args: [{index, text, is_const, is_param}], enclosing_condition, line_number}, ...]`

Uses `xrefs_to` to find callers, then decompiles each caller and locates the call node in the ctree to extract argument expressions and enclosing if/loop conditions.

#### `ctree_vars`
Extract variable information from a decompiled function.

```
ctree_vars(
    addr: "Function address or name",
    filter: "Optional name/type filter"
) -> list[dict]
```

Returns: `[{name, type, is_param, is_stack, size, def_count, use_count, source}, ...]`

Uses `cfunc_t.lvars` and the ctree to count definitions and uses. `source` indicates whether the variable comes from a parameter, return value, global, or local computation. Leverages IDA 9.3 `udt_type_data_t.deduplicate_members()` for struct field accuracy.

### api_microcode.py — Microcode Def-Use Engine

#### `mcode_defuse`
Extract def-use chain for a variable at a given address.

```
mcode_defuse(
    func_addr: "Function address or name",
    var: "Variable name or 'all'",
    maturity: "Microcode maturity level" = "MMAT_GLBOPT1"
) -> list[dict]
```

Returns: `[{var_name, definitions: [{addr, text}], uses: [{addr, text, context}]}, ...]`

Obtains `mba_t` via `ida_hexrays.gen_microcode()` at the requested maturity level. Walks `mblock_t` chains to collect def and use sites for each `mop_t`.

Maturity levels: `MMAT_GENERATED`, `MMAT_PREOPTIMIZED`, `MMAT_LOCOPT`, `MMAT_CALLS`, `MMAT_GLBOPT1`, `MMAT_GLBOPT2`, `MMAT_GLBOPT3`, `MMAT_LVARS`.

#### `mcode_source`
Trace a value backward to its origin — function parameter, global, constant, or return value.

```
mcode_source(
    func_addr: "Function address or name",
    var: "Variable name to trace",
    max_depth: int = 10
) -> dict
```

Returns: `{var, origin_type: "param"|"global"|"const"|"retval"|"unknown", origin_detail, chain: [{addr, text, step}]}`

Backward walks the def-use chain from `mcode_defuse`, following assignments until reaching a terminal (parameter, global read, constant load, or function return value).

#### `mcode_inspect`
Dump microcode IR for a function at a given maturity level.

```
mcode_inspect(
    func_addr: "Function address or name",
    maturity: str = "MMAT_GLBOPT1",
    block_filter: "Optional block index or range" = None,
    offset: int = 0,
    count: int = 200
) -> dict
```

Returns: `{maturity, block_count, insn_count, blocks: [{index, start_addr, end_addr, instructions: [{addr, opcode, text}], succs, preds}]}`

Uses IDA 9.3 microcode display modes. Paginated by instruction count.

### api_vuln.py — Vulnerability Scan Orchestration

#### `vuln_scan`
Shallow binary-wide vulnerability scan using all active patterns.

```
vuln_scan(
    scope: "Function address/name, or 'all' for entire binary" = "all",
    categories: "Comma-separated: memory, format_string, integer, uaf, missing_check, command_injection, crypto" = "all",
    severity_min: "low, medium, high, critical" = "low",
    offset: int = 0,
    count: int = 100,
    max_functions: int = 500
) -> dict
```

Returns:
```
{
    scanned_functions: int,
    total_findings: int,
    findings: [{
        id: str,
        addr: int,
        func_name: str,
        pattern_name: str,
        category: str,
        severity: str,
        snippet: str,
        confidence: float
    }],
    summary: {by_category: {}, by_severity: {}}
}
```

Orchestration:
1. Enumerate functions (respects `scope` and `max_functions`)
2. Decompile each (with caching — no duplicate decompilation)
3. Run ctree visitor with all active patterns
4. Score and sort findings by severity then confidence
5. Return paginated results

#### `vuln_deep`
Deep analysis of a single finding from `vuln_scan`.

```
vuln_deep(
    addr: "Address of the finding",
    pattern: "Pattern name that triggered",
    include_dataflow: bool = True,
    include_callers: bool = True,
    max_depth: int = 5
) -> dict
```

Returns:
```
{
    finding: {addr, func, pattern, severity},
    ctree_context: {enclosing_function, enclosing_block, nearby_checks},
    data_source: {origin_type, origin_detail, chain},  # from mcode_source
    callers: [{caller, call_context, args}],            # from ctree_callers_of
    exploitability: "likely|possible|unlikely|unknown",
    recommendation: str
}
```

Combines `ctree_match`, `mcode_source`, `ctree_callers_of`, and existing `trace_data_flow` for comprehensive context.

#### `vuln_patterns`
List all registered vulnerability patterns.

```
vuln_patterns(
    category: "Filter by category" = "all",
    include_builtin: bool = True,
    include_runtime: bool = True
) -> list[dict]
```

Returns: `[{name, category, severity, description, targets, check_type, is_builtin}, ...]`

#### `vuln_pattern_add` (@unsafe)
Register a new vulnerability pattern at runtime.

```
vuln_pattern_add(
    name: "Unique pattern name",
    category: "memory|format_string|integer|uaf|missing_check|command_injection|custom",
    severity: "low|medium|high|critical",
    targets: "Comma-separated function names to match",
    check: "Check type: arg_size_unbounded, return_unchecked, format_user_controlled, integer_overflow_risk, use_after_free, double_free, command_injection, custom_call_pattern",
    arg_index: int = -1,
    description: str = ""
) -> dict
```

Returns: `{success: bool, name: str, message: str}`

Patterns persist for the session only (not saved to IDB). Declarative config only — no arbitrary code execution.

#### `crypto_scan`
Scan for known cryptographic constants and algorithm signatures.

```
crypto_scan(
    scope: "Function address or 'all'" = "all",
    algorithms: "Comma-separated: aes, sha1, sha256, sha512, md5, tea, xtea, rc4, blowfish, crc32, base64, chacha, all" = "all"
) -> list[dict]
```

Returns: `[{addr, algorithm, constant_name, confidence, func_context, byte_preview}, ...]`

Built-in constant database:
- AES: S-box (0x637c777b...), round constants
- SHA-256: K constants (0x428a2f98...), init vectors (0x6a09e667...)
- SHA-1: init vectors (0x67452301...)
- MD5: init vectors (0x67452301...), T constants
- TEA/XTEA: delta (0x9e3779b9)
- RC4: permutation table heuristic (256-byte sequential array)
- Blowfish: P-array init values
- CRC32: polynomial table (0xedb88320...)
- Base64: alphabet table ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef...")
- ChaCha20: "expand 32-byte k" constant

Uses existing `find()` with `type="immediate"` for 4/8-byte constants, and `find_bytes()` for multi-byte sequences (S-boxes, tables).

#### `attack_surface`
Map input entry points and trace them to dangerous sinks.

```
attack_surface(
    sink_categories: "Comma-separated: memory, format, command, file, network, all" = "all",
    max_depth: int = 5,
    offset: int = 0,
    count: int = 50
) -> dict
```

Returns:
```
{
    input_points: [{func, type: "network|file|stdin|argv|env", callers_count}],
    dangerous_sinks: [{func, category, callers_count}],
    reachable_paths: [{source, sink, depth, intermediate_funcs}],
    summary: {total_inputs, total_sinks, connected_paths}
}
```

Input function database (platform-agnostic):
- Network: `recv`, `recvfrom`, `recvmsg`, `read` (on socket fd), `WSARecv`
- File: `fread`, `fgets`, `read`, `ReadFile`
- Stdin: `scanf`, `gets`, `getchar`, `fgets(stdin)`
- Argv: references to `argc`/`argv`, `GetCommandLine`
- Environment: `getenv`, `GetEnvironmentVariable`

Dangerous sink database:
- Memory: `memcpy`, `memmove`, `strcpy`, `strcat`, `strncpy`, `sprintf`
- Format: `printf`, `fprintf`, `sprintf`, `syslog`, `NSLog`
- Command: `system`, `popen`, `exec*`, `ShellExecute`, `WinExec`, `CreateProcess`
- File: `fopen`, `open`, `CreateFile` (path injection)

Uses `imports_query` to find which sinks/sources exist, `xref_query` for callers, `callgraph` for reachability between source and sink.

#### `check_mitigations`
Check binary-level security mitigations.

```
check_mitigations() -> dict
```

Returns:
```
{
    file_type: "PE|ELF|MachO|raw",
    mitigations: {
        nx: bool,           # DEP / NX bit
        pie: bool,          # Position Independent Executable
        relro: str,         # "none|partial|full" (ELF only)
        stack_canary: bool, # Stack protector detected
        rwx_segments: [{name, start, end, size}],  # Writeable + executable
        fortify: bool,      # FORTIFY_SOURCE detected (ELF)
    },
    risk_notes: [str]       # Human-readable risk observations
}
```

Reads segment permissions via `ida_segment`, checks for `__stack_chk_fail` import (canary), checks PE characteristics / ELF program headers.

### api_segments.py — Segment Management

#### `list_segments`
List all binary segments with permissions and metadata.

```
list_segments(
    filter: "Optional name or permission filter (e.g., 'rwx', '.text')" = None
) -> list[dict]
```

Returns: `[{name, start, end, size, permissions: "rwx", type, class, bitness, is_loaded}, ...]`

Uses `ida_segment.get_segm_qty()` and `ida_segment.getnseg()`. Handles IDA 9.3 default segment register initialization (`BADSEL`).

#### `segment_xrefs`
Analyze cross-references between segments.

```
segment_xrefs(
    from_segment: "Source segment name or 'all'",
    to_segment: "Target segment name or 'all'",
    xref_type: "code|data|all" = "all",
    offset: int = 0,
    count: int = 200
) -> dict
```

Returns:
```
{
    xrefs: [{from_addr, to_addr, from_segment, to_segment, type, func_context}],
    summary: {total, by_direction: {"text→data": N, ...}}
}
```

### Additions to Existing Files

#### `nop_range` in api_modify.py (@unsafe)
NOP out an address range or specific instructions.

```
nop_range(
    addr: "Start address",
    end: "End address (exclusive)" = None,
    count: "Number of instructions to NOP (alternative to end)" = None,
    nop_calls: "If true and addr points to a CALL, NOP the entire call instruction" = False
) -> dict
```

Returns: `{addr, bytes_patched, instructions_patched, original_bytes}`

Exactly one of `end` or `count` must be provided. Saves original bytes for undo reference.

#### `detect_libs` in api_core.py
Report FLIRT signature matches and library detection.

```
detect_libs(
    confidence_min: float = 0.0,
    offset: int = 0,
    count: int = 100
) -> dict
```

Returns:
```
{
    libraries: [{name, version, matched_functions, total_functions, confidence}],
    unmatched_count: int,
    lumina_available: bool,
    lumina_matches: int  # IDA 9.3: ida_lumina metadata count
}
```

Uses `idautils.Functions()` + `idc.get_func_flags()` to identify library-flagged functions, groups by library name from FLIRT. On IDA 9.3+, queries `ida_lumina` for additional metadata.

## Pattern Engine

### Pattern Registry

Located in `api_vuln.py`. A module-level dict mapping pattern names to pattern configs.

```python
_PATTERN_REGISTRY: dict[str, PatternConfig] = {}
_BUILTIN_LOADED: bool = False
```

Builtin patterns loaded lazily on first `vuln_scan` or `vuln_patterns` call.

### PatternConfig TypedDict

```python
class PatternConfig(TypedDict):
    name: str
    category: str           # memory|format_string|integer|uaf|missing_check|command_injection|custom
    severity: str           # low|medium|high|critical
    targets: list[str]      # function names to match (e.g., ["memcpy", "memmove"])
    check: str              # check type identifier
    arg_index: int          # which argument to inspect (-1 = N/A)
    description: str
    is_builtin: bool
```

### Builtin Patterns (initial set ~25)

**Memory corruption (7):**
- `unchecked_memcpy_size` — memcpy/memmove/bcopy with non-constant, unchecked size arg
- `unchecked_strncpy_size` — strncpy where size > dest buffer (when detectable)
- `unbounded_strcpy` — strcpy/strcat with non-literal source
- `unbounded_sprintf` — sprintf with %s and non-literal arg
- `stack_buffer_overflow` — memcpy/read into stack buffer exceeding declared size
- `heap_overflow_candidate` — malloc'd buffer with subsequent unchecked write
- `off_by_one_loop` — loop bound `<=` instead of `<` on buffer index

**Format string (3):**
- `printf_format_arg` — printf/fprintf/sprintf/syslog where format is not a string literal
- `snprintf_format_arg` — snprintf where format is not a string literal
- `nslog_format_arg` — NSLog (Obj-C) with non-literal format

**Integer issues (3):**
- `integer_overflow_multiply` — multiplication result used as allocation/copy size without overflow check
- `signed_unsigned_compare` — signed/unsigned comparison in size/bounds check
- `integer_truncation` — 64-bit value assigned to 32-bit in size context

**Use-after-free / double-free (3):**
- `use_after_free` — pointer used after free() call without reassignment
- `double_free` — same pointer passed to free() twice on reachable paths
- `free_global_no_null` — free(global_ptr) without setting to NULL afterward

**Missing check (4):**
- `malloc_null_unchecked` — malloc/calloc/realloc return not checked for NULL
- `return_value_ignored` — function with non-void return called as statement (configurable targets)
- `error_path_leak` — resource allocated, error branch exits without freeing
- `unchecked_read_return` — read/recv return value not checked for <= 0

**Command injection (2):**
- `system_user_input` — system/popen/exec with non-literal argument
- `shell_format_construct` — sprintf/snprintf building command string passed to system

**Crypto (3):**
- `hardcoded_key` — constant byte array used as crypto key argument
- `weak_random` — rand/srand used in security context
- `ecb_mode_detected` — ECB mode constant in crypto API calls

### Check Type Engine

Each `check` string maps to a ctree visitor strategy in `api_ctree.py`:

| Check Type | Visitor Logic |
|---|---|
| `arg_size_unbounded` | Find calls to target, check if size arg is: constant (safe), bounded by if/min/ternary (safe), or unbounded (flag) |
| `return_unchecked` | Find calls to target, check if return value is used in comparison or assignment before next use |
| `format_user_controlled` | Find calls to target, check if format arg (index 0 or 1) is a string literal |
| `integer_overflow_risk` | Find multiply/add/shift results flowing into size arguments of alloc/copy functions |
| `use_after_free` | Find free() calls, track pointer through subsequent basic blocks for use before reassignment |
| `double_free` | Find free() calls, track pointer for second free() on all reachable paths |
| `command_injection` | Find calls to target, check if arg is a string literal or contains user-derived data |
| `custom_call_pattern` | Generic: find calls to target, flag if arg at arg_index is not a constant |

### Runtime Pattern Extension

`vuln_pattern_add` adds to `_PATTERN_REGISTRY` with `is_builtin=False`. Patterns persist for the IDA session only. The check types above are reusable — a runtime pattern specifies `targets`, `check`, and `arg_index` to compose new detections without code changes.

## Crypto Constant Database

Embedded in `api_vuln.py` as a module-level dict:

```python
CRYPTO_CONSTANTS: dict[str, list[dict]] = {
    "aes": [
        {"name": "AES S-box", "bytes": "637c777bf26b6fc5...", "type": "bytes", "min_match": 16},
        {"name": "AES Rcon", "values": [0x01, 0x02, 0x04, ...], "type": "immediate"},
    ],
    "sha256": [
        {"name": "SHA-256 K[0]", "values": [0x428a2f98, 0x71374491, ...], "type": "immediate"},
        {"name": "SHA-256 H[0]", "values": [0x6a09e667, 0xbb67ae85, ...], "type": "immediate"},
    ],
    # ... md5, sha1, sha512, tea, xtea, rc4, blowfish, crc32, base64, chacha
}
```

`crypto_scan` iterates this database, using `find(type="immediate")` for single values and `find_bytes()` for byte sequences. Match confidence based on how many consecutive constants found.

## IDA 9.3 Feature Usage

| Feature | Used In | How |
|---|---|---|
| `ida_lumina` module | `detect_libs` | Query Lumina metadata for function names/types from cloud |
| `tinfo_t.is_iface()` | `ctree_vars` | Detect Obj-C interface types for iOS/macOS targets |
| `udt_type_data_t.deduplicate_members()` | `ctree_vars` | Accurate struct field resolution |
| Microcode display modes | `mcode_inspect` | Richer IR output formatting |
| Microcode assertion insert | Future (Phase C) | Mark taint boundaries in IR |
| Built-in Clang parser | Future | SDK header import for type-aware analysis |
| Dirtree API | Not planned | Organizational, not vuln-relevant |

Version guard: all 9.3-specific features gated behind `compat.py` version checks. Graceful fallback on IDA 9.0-9.2.

## Performance Design

- **Decompile cache:** `vuln_scan` decompiles each function once, reuses `cfunc_t` across all patterns. Cache keyed by function start address, invalidated per scan.
- **Pagination:** All list-returning tools support `offset/count`. Default limits chosen for MCP response size.
- **Function limits:** `vuln_scan` default `max_functions=500`, max `5000`. Large binaries require pagination.
- **Microcode maturity:** Default `MMAT_GLBOPT1` — good balance of optimization and speed. Configurable per-call.
- **Early termination:** Pattern matching stops after `count` matches, doesn't scan remaining functions.
- **Thread safety:** All tools use `@tool @idasync`. Ctree visitors and microcode generation run on IDA main thread.

## Module Dependencies

```
api_vuln.py
  ├── api_ctree.py (ctree_match, ctree_callers_of)
  ├── api_microcode.py (mcode_source)
  ├── api_analysis.py (find, find_bytes, xref_query, decompile) [existing]
  ├── api_core.py (list_funcs, imports_query) [existing]
  └── api_composite.py (trace_data_flow) [existing]

api_ctree.py
  └── (no new module dependencies, uses ida_hexrays directly)

api_microcode.py
  └── (no new module dependencies, uses ida_hexrays directly)

api_segments.py
  └── (no new module dependencies, uses ida_segment directly)
```

No circular dependencies. `api_vuln.py` is the only orchestration layer.

## Implementation Phases

### Phase 1: Ctree Engine (`api_ctree.py`)
Foundation layer. All vulnerability detection depends on this.
- `ctree_query`, `ctree_match`, `ctree_callers_of`, `ctree_vars`
- Check type engine (visitor strategies)
- **Code review checkpoint**

### Phase 2: Microcode Engine (`api_microcode.py`)
Enables deep analysis and data source tracking.
- `mcode_defuse`, `mcode_source`, `mcode_inspect`
- **Code review checkpoint**

### Phase 3: Vuln Orchestration (`api_vuln.py`)
Ties everything together. Includes pattern registry and all scan tools.
- Pattern registry + ~25 builtin patterns
- `vuln_scan`, `vuln_deep`, `vuln_patterns`, `vuln_pattern_add`
- `crypto_scan`, `attack_surface`, `check_mitigations`
- Crypto constant database
- **Code review checkpoint**

### Phase 4: Segments + Utilities (`api_segments.py` + existing file additions)
Lower-risk additions to complete the suite.
- `list_segments`, `segment_xrefs`
- `nop_range` (in api_modify.py)
- `detect_libs` (in api_core.py)
- **Code review checkpoint**

### Phase 5: Integration + Final Review
- End-to-end testing with `crackme03.elf` and `typed_fixture.elf`
- Full code review of all new modules
- CLAUDE.md update with new tool documentation

### Future: Phase C (Roadmap)
Full taint propagation via microcode — not in this implementation cycle.
- Cross-function taint tracking
- `ida_lumina` deep integration
- Microcode assertion insertion for taint boundaries
- Built-in Clang parser for SDK type import

## Testing Strategy

### Test Fixtures
- `tests/crackme03.elf` — crackme patterns, comparison detection, crypto constants
- `tests/typed_fixture.elf` — type/struct patterns, variable tracking

### Test Coverage Per Module
- `api_ctree.py`: Each node type query, each check type (positive + negative), pagination
- `api_microcode.py`: Def-use chain extraction, source tracing, maturity level handling
- `api_vuln.py`: Pattern registry CRUD, scan pagination, crypto constant matching, attack surface mapping
- `api_segments.py`: Segment listing, permission parsing, cross-segment xrefs

### Code Review Checkpoints
Each phase ends with `superpowers:requesting-code-review` agent review:
1. Post-Phase 1: ctree engine correctness, visitor pattern safety
2. Post-Phase 2: microcode API usage, maturity level handling
3. Post-Phase 3: pattern engine completeness, false positive assessment
4. Post-Phase 4: segment API usage, nop_range safety
5. Post-Phase 5: full integration review, performance assessment
