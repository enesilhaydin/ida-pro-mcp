"""Decompiler AST (ctree) traversal engine with vulnerability pattern matching.

Provides 4 MCP tools:
- ctree_query: Query ctree AST nodes by type/filter
- ctree_match: Match vulnerability patterns against decompiled functions
- ctree_callers_of: Find all call sites with ctree context
- ctree_vars: Extract variable information from decompiled functions

Also exposes a pattern registry (~25 builtin patterns) via get_pattern_registry().
"""

from typing import Annotated, NotRequired, TypedDict
import ida_hexrays
import ida_funcs
import ida_bytes
import idaapi
import idautils
import ida_name

from .rpc import tool
from .sync import idasync, IDAError
from .utils import normalize_list_input, parse_address


# ============================================================================
# TypedDicts
# ============================================================================


class CtreeNode(TypedDict):
    addr: str
    node_type: str
    text: str
    error: NotRequired[str]


class CtreeMatchResult(TypedDict):
    addr: str
    func_name: str
    pattern_name: str
    category: str
    severity: str
    snippet: str
    match_detail: NotRequired[str]


class CtreeCallerResult(TypedDict):
    caller_addr: str
    caller_name: str
    call_addr: str
    args: list[str]
    enclosing_condition: NotRequired[str]


class CtreeVarInfo(TypedDict):
    name: str
    type: str
    is_param: bool
    is_stack: bool
    size: int
    source: str


class PatternConfig(TypedDict):
    name: str
    category: str        # memory|format_string|integer|uaf|missing_check|command_injection|crypto|custom
    severity: str        # low|medium|high|critical
    targets: list[str]   # function names to match
    check: str           # check type identifier
    arg_index: int       # which argument (-1 = N/A)
    description: str
    is_builtin: bool


# ============================================================================
# Pattern Registry
# ============================================================================

_PATTERN_REGISTRY: dict[str, PatternConfig] = {}
_patterns_loaded = False


def _load_builtin_patterns() -> None:
    global _patterns_loaded
    if _patterns_loaded:
        return
    _patterns_loaded = True

    builtin: list[PatternConfig] = [
        # --- Memory (7) ---
        {
            "name": "unchecked_memcpy_size",
            "category": "memory",
            "severity": "high",
            "targets": ["memcpy", "_memcpy"],
            "check": "arg_size_unbounded",
            "arg_index": 2,
            "description": "memcpy size argument is not a bounded constant",
            "is_builtin": True,
        },
        {
            "name": "unbounded_strcpy",
            "category": "memory",
            "severity": "high",
            "targets": ["strcpy", "_strcpy", "lstrcpyA", "lstrcpyW"],
            "check": "custom_call_pattern",
            "arg_index": 0,
            "description": "strcpy with no bounds check — always unsafe",
            "is_builtin": True,
        },
        {
            "name": "unbounded_sprintf",
            "category": "memory",
            "severity": "high",
            "targets": ["sprintf", "_sprintf", "__sprintf_chk"],
            "check": "format_user_controlled",
            "arg_index": 1,
            "description": "sprintf without bounds — prefer snprintf",
            "is_builtin": True,
        },
        {
            "name": "stack_buffer_gets",
            "category": "memory",
            "severity": "critical",
            "targets": ["gets", "_gets"],
            "check": "custom_call_pattern",
            "arg_index": 0,
            "description": "gets() has no length limit and is inherently unsafe",
            "is_builtin": True,
        },
        {
            "name": "unchecked_strncpy_size",
            "category": "memory",
            "severity": "medium",
            "targets": ["strncpy", "_strncpy"],
            "check": "arg_size_unbounded",
            "arg_index": 2,
            "description": "strncpy size argument is not a bounded constant",
            "is_builtin": True,
        },
        {
            "name": "heap_overflow_read",
            "category": "memory",
            "severity": "high",
            "targets": ["memcpy", "memmove", "_memcpy", "_memmove"],
            "check": "integer_overflow_risk",
            "arg_index": 2,
            "description": "Potential integer overflow in heap copy size",
            "is_builtin": True,
        },
        {
            "name": "off_by_one_memset",
            "category": "memory",
            "severity": "medium",
            "targets": ["memset", "_memset"],
            "check": "arg_size_unbounded",
            "arg_index": 2,
            "description": "memset size argument may be unbounded or off-by-one",
            "is_builtin": True,
        },
        # --- Format string (3) ---
        {
            "name": "printf_format_arg",
            "category": "format_string",
            "severity": "high",
            "targets": ["printf", "_printf", "fprintf", "vprintf"],
            "check": "format_user_controlled",
            "arg_index": 0,
            "description": "printf format string argument is not a string literal",
            "is_builtin": True,
        },
        {
            "name": "snprintf_format_arg",
            "category": "format_string",
            "severity": "medium",
            "targets": ["snprintf", "_snprintf", "vsnprintf"],
            "check": "format_user_controlled",
            "arg_index": 2,
            "description": "snprintf format string argument is not a string literal",
            "is_builtin": True,
        },
        {
            "name": "nslog_format_arg",
            "category": "format_string",
            "severity": "medium",
            "targets": ["NSLog", "CFStringCreateWithFormat"],
            "check": "format_user_controlled",
            "arg_index": 0,
            "description": "NSLog/CFStringCreateWithFormat format arg is not a literal",
            "is_builtin": True,
        },
        # --- Integer (3) ---
        {
            "name": "integer_overflow_multiply",
            "category": "integer",
            "severity": "high",
            "targets": ["malloc", "calloc", "realloc", "_malloc"],
            "check": "integer_overflow_risk",
            "arg_index": 0,
            "description": "Potential integer overflow in allocation size expression",
            "is_builtin": True,
        },
        {
            "name": "signed_unsigned_compare",
            "category": "integer",
            "severity": "medium",
            "targets": ["memcpy", "memmove", "read", "fread", "recv"],
            "check": "arg_size_unbounded",
            "arg_index": 2,
            "description": "Signed/unsigned mismatch in size argument",
            "is_builtin": True,
        },
        {
            "name": "integer_truncation",
            "category": "integer",
            "severity": "medium",
            "targets": ["memcpy", "strcpy", "strncpy", "malloc"],
            "check": "integer_overflow_risk",
            "arg_index": -1,
            "description": "Potential integer truncation in argument expression",
            "is_builtin": True,
        },
        # --- UAF (3) ---
        {
            "name": "use_after_free",
            "category": "uaf",
            "severity": "critical",
            "targets": ["free", "_free"],
            "check": "use_after_free",
            "arg_index": 0,
            "description": "Memory used after free()",
            "is_builtin": True,
        },
        {
            "name": "double_free",
            "category": "uaf",
            "severity": "critical",
            "targets": ["free", "_free"],
            "check": "double_free",
            "arg_index": 0,
            "description": "Memory freed twice without intervening allocation",
            "is_builtin": True,
        },
        {
            "name": "free_global_no_null",
            "category": "uaf",
            "severity": "medium",
            "targets": ["free", "_free"],
            "check": "custom_call_pattern",
            "arg_index": 0,
            "description": "Global/static pointer freed without null-check or null-assignment after",
            "is_builtin": True,
        },
        # --- Missing check (4) ---
        {
            "name": "malloc_null_unchecked",
            "category": "missing_check",
            "severity": "high",
            "targets": ["malloc", "calloc", "realloc", "_malloc"],
            "check": "return_unchecked",
            "arg_index": -1,
            "description": "Return value of malloc/calloc/realloc not checked for NULL",
            "is_builtin": True,
        },
        {
            "name": "return_value_ignored_io",
            "category": "missing_check",
            "severity": "medium",
            "targets": ["fwrite", "fread", "write", "read", "send", "recv"],
            "check": "return_unchecked",
            "arg_index": -1,
            "description": "Return value of I/O function is ignored",
            "is_builtin": True,
        },
        {
            "name": "unchecked_read_return",
            "category": "missing_check",
            "severity": "medium",
            "targets": ["read", "fread", "recv", "recvfrom"],
            "check": "return_unchecked",
            "arg_index": -1,
            "description": "Return value of read/recv not checked for errors or short reads",
            "is_builtin": True,
        },
        {
            "name": "error_path_leak",
            "category": "missing_check",
            "severity": "medium",
            "targets": ["open", "fopen", "socket", "accept"],
            "check": "return_unchecked",
            "arg_index": -1,
            "description": "Return value of resource-opening call not checked",
            "is_builtin": True,
        },
        # --- Command injection (2) ---
        {
            "name": "system_user_input",
            "category": "command_injection",
            "severity": "critical",
            "targets": ["system", "_system", "popen"],
            "check": "command_injection",
            "arg_index": 0,
            "description": "system()/popen() called with non-literal argument (possible injection)",
            "is_builtin": True,
        },
        {
            "name": "shell_format_construct",
            "category": "command_injection",
            "severity": "critical",
            "targets": ["execl", "execle", "execlp", "execv", "execve", "execvp"],
            "check": "command_injection",
            "arg_index": 0,
            "description": "exec*() called with non-literal path argument",
            "is_builtin": True,
        },
        # --- Crypto (2) ---
        {
            "name": "hardcoded_key",
            "category": "crypto",
            "severity": "high",
            "targets": ["AES_set_encrypt_key", "AES_set_decrypt_key", "EVP_EncryptInit",
                        "CCCrypt", "SecItemAdd"],
            "check": "custom_call_pattern",
            "arg_index": 0,
            "description": "Hardcoded key material passed to crypto function",
            "is_builtin": True,
        },
        {
            "name": "weak_random",
            "category": "crypto",
            "severity": "medium",
            "targets": ["rand", "random", "srand", "drand48"],
            "check": "custom_call_pattern",
            "arg_index": -1,
            "description": "Weak PRNG used — not suitable for security-sensitive values",
            "is_builtin": True,
        },
    ]

    for p in builtin:
        _PATTERN_REGISTRY[p["name"]] = p


def get_pattern_registry() -> dict[str, PatternConfig]:
    """Return the global pattern registry (lazy-loaded on first call)."""
    _load_builtin_patterns()
    return _PATTERN_REGISTRY


# ============================================================================
# Internal helpers
# ============================================================================

# ctree node-type name mapping (cit_* = statement, cot_* = expression)
_NODE_TYPE_MAP: dict[int, str] = {}

def _init_node_type_map() -> None:
    """Populate _NODE_TYPE_MAP from ida_hexrays constants."""
    global _NODE_TYPE_MAP
    if _NODE_TYPE_MAP:
        return
    pairs = [
        ("call",      [ida_hexrays.cot_call]),
        ("assign",    [ida_hexrays.cot_asg, ida_hexrays.cot_asgadd,
                       ida_hexrays.cot_asgmul, ida_hexrays.cot_asgsub,
                       ida_hexrays.cot_asgsdiv, ida_hexrays.cot_asgsmod,
                       ida_hexrays.cot_asgudiv, ida_hexrays.cot_asgumod,
                       ida_hexrays.cot_asgband, ida_hexrays.cot_asgbor,
                       ida_hexrays.cot_asgxor, ida_hexrays.cot_asgshl,
                       ida_hexrays.cot_asgshr]),
        ("compare",   [ida_hexrays.cot_eq, ida_hexrays.cot_ne,
                       ida_hexrays.cot_slt, ida_hexrays.cot_sle,
                       ida_hexrays.cot_sgt, ida_hexrays.cot_sge,
                       ida_hexrays.cot_ult, ida_hexrays.cot_ule,
                       ida_hexrays.cot_ugt, ida_hexrays.cot_uge]),
        ("return",    [ida_hexrays.cit_return]),
        ("if",        [ida_hexrays.cit_if]),
        ("loop",      [ida_hexrays.cit_for, ida_hexrays.cit_while,
                       ida_hexrays.cit_do]),
        ("cast",      [ida_hexrays.cot_cast]),
        ("ref",       [ida_hexrays.cot_ref]),
    ]
    for label, ops in pairs:
        for op in ops:
            _NODE_TYPE_MAP[op] = label


_LABEL_TO_OPS: dict[str, list[int]] = {}

def _init_label_to_ops() -> None:
    global _LABEL_TO_OPS
    if _LABEL_TO_OPS:
        return
    _init_node_type_map()
    for op, label in _NODE_TYPE_MAP.items():
        _LABEL_TO_OPS.setdefault(label, []).append(op)


def _get_call_name(expr: "ida_hexrays.cexpr_t") -> str:
    """Extract called function name from a cot_call expression."""
    if expr.op != ida_hexrays.cot_call:
        return ""
    fn = expr.x
    if fn.op == ida_hexrays.cot_obj:
        name = ida_name.get_short_name(fn.obj_ea)
        if name:
            return name
    # fallback
    try:
        return fn.dstr()
    except Exception:
        return ""


def _is_string_literal_arg(arg: "ida_hexrays.cexpr_t") -> bool:
    """Return True if arg is a string literal (constant string)."""
    # Direct string literal
    if arg.op == ida_hexrays.cot_str:
        return True
    # Cast of something — unwrap
    if arg.op == ida_hexrays.cot_cast:
        return _is_string_literal_arg(arg.x)
    # Object reference — check if it points to a string
    if arg.op == ida_hexrays.cot_obj:
        return ida_bytes.is_strlit(ida_bytes.get_flags(arg.obj_ea))
    # Reference to object
    if arg.op == ida_hexrays.cot_ref:
        return _is_string_literal_arg(arg.x)
    return False


def _is_constant_arg(arg: "ida_hexrays.cexpr_t") -> bool:
    """Return True if arg is a numeric constant."""
    if arg.op in (ida_hexrays.cot_num, ida_hexrays.cot_fnum):
        return True
    if arg.op == ida_hexrays.cot_cast:
        return _is_constant_arg(arg.x)
    return False


def _has_arithmetic_in_arg(arg: "ida_hexrays.cexpr_t") -> bool:
    """Return True if arg contains multiply/add/shift (overflow risk)."""
    ARITH_OPS = {
        ida_hexrays.cot_mul, ida_hexrays.cot_add, ida_hexrays.cot_sub,
        ida_hexrays.cot_shl, ida_hexrays.cot_sdiv, ida_hexrays.cot_udiv,
        ida_hexrays.cot_smul, ida_hexrays.cot_umul,
    }
    if arg.op in ARITH_OPS:
        return True
    # recurse into children
    for child_attr in ("x", "y", "z"):
        child = getattr(arg, child_attr, None)
        if child is not None and isinstance(child, ida_hexrays.cexpr_t):
            if _has_arithmetic_in_arg(child):
                return True
    return False


def _cfunc_from_addr(addr: str) -> "ida_hexrays.cfunc_t":
    """Decompile function at addr, raising IDAError on failure."""
    ea = parse_address(addr)
    func = ida_funcs.get_func(ea)
    if func is None:
        raise IDAError(f"No function at {addr}")
    hf = ida_hexrays.hexrays_failure_t()
    cfunc = ida_hexrays.decompile(func.start_ea, hf)
    if cfunc is None:
        raise IDAError(f"Decompilation failed: {hf.desc()}")
    return cfunc


# ============================================================================
# Visitor: collect nodes
# ============================================================================

class _NodeCollector(ida_hexrays.ctree_visitor_t):
    """Collect ctree nodes matching a set of opcodes."""

    def __init__(self, wanted_ops: set[int] | None = None):
        super().__init__(ida_hexrays.CV_FAST)
        self.wanted_ops = wanted_ops  # None means all
        self.nodes: list[tuple[int, int, str]] = []  # (ea, op, text)

    def visit_expr(self, expr: "ida_hexrays.cexpr_t") -> int:
        self._check(expr)
        return 0

    def visit_insn(self, insn: "ida_hexrays.cinsn_t") -> int:
        self._check(insn)
        return 0

    def _check(self, node) -> None:
        op = node.op
        if self.wanted_ops is not None and op not in self.wanted_ops:
            return
        label = _NODE_TYPE_MAP.get(op, f"op_{op}")
        ea = getattr(node, "ea", idaapi.BADADDR)
        try:
            text = node.dstr()
        except Exception:
            text = f"<{label}>"
        self.nodes.append((ea, op, text))


# ============================================================================
# Tool 1: ctree_query
# ============================================================================

@tool
@idasync
def ctree_query(
    addr: Annotated[str, "Function address or name"],
    node_types: Annotated[str, "Comma-separated node types: call,assign,compare,return,if,loop,cast,ref or 'all'"] = "all",
    filter: Annotated[str, "Substring filter applied to node text"] = "",
    offset: Annotated[int, "Pagination offset"] = 0,
    count: Annotated[int, "Max results to return"] = 100,
) -> list[CtreeNode]:
    """Query ctree AST nodes in a decompiled function by type and optional text filter.

    Walks the Hex-Rays ctree for the function at addr and returns matching nodes.
    node_types can be 'all' or a comma-separated list of: call, assign, compare,
    return, if, loop, cast, ref.
    """
    _init_node_type_map()
    _init_label_to_ops()

    try:
        cfunc = _cfunc_from_addr(addr)
    except IDAError as e:
        return [{"addr": addr, "node_type": "error", "text": "", "error": str(e)}]

    # Build set of wanted opcodes
    wanted_ops: set[int] | None = None
    if node_types and node_types.strip().lower() != "all":
        wanted_ops = set()
        for nt in node_types.split(","):
            nt = nt.strip().lower()
            ops = _LABEL_TO_OPS.get(nt, [])
            wanted_ops.update(ops)

    collector = _NodeCollector(wanted_ops)
    collector.apply_to(cfunc.body, None)

    results: list[CtreeNode] = []
    for ea, op, text in collector.nodes:
        if filter and filter.lower() not in text.lower():
            continue
        label = _NODE_TYPE_MAP.get(op, f"op_{op}")
        results.append({
            "addr": hex(ea) if ea != idaapi.BADADDR else addr,
            "node_type": label,
            "text": text,
        })

    # paginate
    return results[offset: offset + count] if count > 0 else results[offset:]


# ============================================================================
# Visitor: find calls to specific targets
# ============================================================================

class _CallFinder(ida_hexrays.ctree_visitor_t):
    """Collect all cot_call expressions targeting a given set of function names.

    Also tracks which calls appear directly inside a cit_expr statement
    (i.e. the return value is discarded) via the expr_stmt_calls set.
    """

    def __init__(self, targets: set[str]):
        super().__init__(ida_hexrays.CV_FAST)
        self.targets = targets
        self.calls: list["ida_hexrays.cexpr_t"] = []
        # Set of call expression ids whose return value is discarded
        self.expr_stmt_calls: set[int] = set()

    def visit_insn(self, insn: "ida_hexrays.cinsn_t") -> int:
        # cit_expr: an expression used as a statement — return value ignored
        if insn.op == ida_hexrays.cit_expr:
            expr = insn.cexpr
            if expr is not None and expr.op == ida_hexrays.cot_call:
                self.expr_stmt_calls.add(id(expr))
        return 0

    def visit_expr(self, expr: "ida_hexrays.cexpr_t") -> int:
        if expr.op == ida_hexrays.cot_call:
            name = _get_call_name(expr)
            # strip leading underscore variants
            bare = name.lstrip("_")
            if name in self.targets or bare in self.targets:
                self.calls.append(expr)
        return 0


# ============================================================================
# Check engine helpers
# ============================================================================

def _check_arg_size_unbounded(call: "ida_hexrays.cexpr_t", arg_index: int) -> tuple[bool, str]:
    args = call.a
    if arg_index < 0 or arg_index >= len(args):
        return False, ""
    arg = args[arg_index]
    if _is_constant_arg(arg):
        return False, ""
    try:
        snippet = arg.dstr()
    except Exception:
        snippet = "<arg>"
    return True, f"size arg [{arg_index}] is not constant: {snippet}"


def _check_format_user_controlled(call: "ida_hexrays.cexpr_t", arg_index: int) -> tuple[bool, str]:
    args = call.a
    if arg_index < 0 or arg_index >= len(args):
        return False, ""
    arg = args[arg_index]
    if _is_string_literal_arg(arg):
        return False, ""
    try:
        snippet = arg.dstr()
    except Exception:
        snippet = "<arg>"
    return True, f"format arg [{arg_index}] is not a string literal: {snippet}"


def _check_return_unchecked(
    call: "ida_hexrays.cexpr_t",
    expr_stmt_call_ids: set[int],
) -> tuple[bool, str]:
    """Return True if the call result is unused (appears in an expression statement).

    Uses the pre-collected set of call-expression ids that were observed as
    direct children of cit_expr instructions, avoiding the non-public
    cfunc.body.find_parent_of() API.
    """
    if id(call) in expr_stmt_call_ids:
        return True, "return value is discarded (expression statement)"
    return False, ""


def _check_integer_overflow_risk(call: "ida_hexrays.cexpr_t", arg_index: int) -> tuple[bool, str]:
    args = call.a
    if arg_index < 0:
        # check all args
        for i, arg in enumerate(args):
            if _has_arithmetic_in_arg(arg):
                try:
                    snippet = arg.dstr()
                except Exception:
                    snippet = "<arg>"
                return True, f"arithmetic in arg [{i}]: {snippet}"
        return False, ""
    if arg_index >= len(args):
        return False, ""
    arg = args[arg_index]
    if _has_arithmetic_in_arg(arg):
        try:
            snippet = arg.dstr()
        except Exception:
            snippet = "<arg>"
        return True, f"arithmetic in size arg [{arg_index}]: {snippet}"
    return False, ""


def _check_command_injection(call: "ida_hexrays.cexpr_t", arg_index: int) -> tuple[bool, str]:
    args = call.a
    if arg_index < 0 or arg_index >= len(args):
        return False, ""
    arg = args[arg_index]
    if _is_string_literal_arg(arg):
        return False, ""
    try:
        snippet = arg.dstr()
    except Exception:
        snippet = "<arg>"
    return True, f"non-literal command arg [{arg_index}]: {snippet}"


def _check_use_after_free(call: "ida_hexrays.cexpr_t", cfunc: "ida_hexrays.cfunc_t") -> tuple[bool, str]:
    """Simple heuristic: look for the freed variable being used in the same function body."""
    args = call.a
    if not args:
        return False, ""
    freed_arg = args[0]
    try:
        freed_text = freed_arg.dstr()
    except Exception:
        return False, ""

    # Walk all expressions looking for a use of the same variable after this free
    class _UseAfterFreeChecker(ida_hexrays.ctree_visitor_t):
        def __init__(self, freed_ea: int, free_call_ea: int):
            super().__init__(ida_hexrays.CV_FAST)
            self.freed_ea = freed_ea
            self.free_call_ea = free_call_ea
            self.found = False

        def visit_expr(self, expr: "ida_hexrays.cexpr_t") -> int:
            if (expr.op == ida_hexrays.cot_obj and
                    expr.obj_ea == self.freed_ea and
                    expr.ea > self.free_call_ea):
                self.found = True
                return 1  # stop
            return 0

    if freed_arg.op == ida_hexrays.cot_obj:
        checker = _UseAfterFreeChecker(freed_arg.obj_ea, call.ea)
        checker.apply_to(cfunc.body, None)
        if checker.found:
            return True, f"variable {freed_text} used after free()"
    return False, ""


def _check_double_free(call: "ida_hexrays.cexpr_t", cfunc: "ida_hexrays.cfunc_t") -> tuple[bool, str]:
    """Check if the same address is passed to free() more than once."""
    args = call.a
    if not args:
        return False, ""
    freed_arg = args[0]
    if freed_arg.op != ida_hexrays.cot_obj:
        return False, ""

    freed_ea = freed_arg.obj_ea

    class _DoubleFreeChecker(ida_hexrays.ctree_visitor_t):
        def __init__(self, target_obj_ea: int, first_call_ea: int):
            super().__init__(ida_hexrays.CV_FAST)
            self.target_obj_ea = target_obj_ea
            self.first_call_ea = first_call_ea
            self.second_free_found = False

        def visit_expr(self, expr: "ida_hexrays.cexpr_t") -> int:
            if expr.op == ida_hexrays.cot_call and expr.ea != self.first_call_ea:
                name = _get_call_name(expr)
                if name.lstrip("_") in ("free",):
                    sub_args = expr.a
                    if sub_args and sub_args[0].op == ida_hexrays.cot_obj:
                        if sub_args[0].obj_ea == self.target_obj_ea:
                            self.second_free_found = True
                            return 1
            return 0

    checker = _DoubleFreeChecker(freed_ea, call.ea)
    checker.apply_to(cfunc.body, None)
    if checker.second_free_found:
        try:
            snippet = freed_arg.dstr()
        except Exception:
            snippet = "<arg>"
        return True, f"double free of {snippet}"
    return False, ""


def _check_custom_call_pattern(call: "ida_hexrays.cexpr_t", arg_index: int) -> tuple[bool, str]:
    """Generic: always matches (the call itself is the finding)."""
    try:
        snippet = call.dstr()[:80]
    except Exception:
        snippet = "<call>"
    return True, f"matched call: {snippet}"


def _run_check(
    pattern: PatternConfig,
    call: "ida_hexrays.cexpr_t",
    cfunc: "ida_hexrays.cfunc_t",
    expr_stmt_call_ids: set[int] | None = None,
) -> tuple[bool, str]:
    check = pattern["check"]
    arg_index = pattern["arg_index"]
    if check == "arg_size_unbounded":
        return _check_arg_size_unbounded(call, arg_index)
    elif check == "format_user_controlled":
        return _check_format_user_controlled(call, arg_index)
    elif check == "return_unchecked":
        return _check_return_unchecked(call, expr_stmt_call_ids or set())
    elif check == "integer_overflow_risk":
        return _check_integer_overflow_risk(call, arg_index)
    elif check == "use_after_free":
        return _check_use_after_free(call, cfunc)
    elif check == "double_free":
        return _check_double_free(call, cfunc)
    elif check == "command_injection":
        return _check_command_injection(call, arg_index)
    elif check == "custom_call_pattern":
        return _check_custom_call_pattern(call, arg_index)
    return False, ""


# Public alias for use by api_vuln.py and other callers
run_check = _run_check


def _match_patterns_in_cfunc(
    cfunc: "ida_hexrays.cfunc_t",
    patterns: list[PatternConfig],
    func_addr: int,
    func_name: str,
) -> list[CtreeMatchResult]:
    results: list[CtreeMatchResult] = []
    for pattern in patterns:
        targets = set(pattern["targets"])
        finder = _CallFinder(targets)
        finder.apply_to(cfunc.body, None)
        for call in finder.calls:
            matched, detail = _run_check(pattern, call, cfunc, finder.expr_stmt_call_ids)
            if matched:
                try:
                    snippet = call.dstr()[:120]
                except Exception:
                    snippet = "<call>"
                entry: CtreeMatchResult = {
                    "addr": hex(func_addr),
                    "func_name": func_name,
                    "pattern_name": pattern["name"],
                    "category": pattern["category"],
                    "severity": pattern["severity"],
                    "snippet": snippet,
                }
                if detail:
                    entry["match_detail"] = detail
                results.append(entry)
    return results


# Public alias for use by api_vuln.py
match_function = _match_patterns_in_cfunc


# ============================================================================
# Tool 2: ctree_match
# ============================================================================

@tool
@idasync
def ctree_match(
    addr: Annotated[str, "Function address/name or 'all' to scan every function"] = "all",
    pattern: Annotated[str, "Pattern name, comma-separated names, or 'all'"] = "all",
    categories: Annotated[str, "Category filter: memory,format_string,integer,uaf,missing_check,command_injection,crypto or 'all'"] = "all",
    offset: Annotated[int, "Pagination offset"] = 0,
    count: Annotated[int, "Max results to return"] = 200,
) -> list[CtreeMatchResult]:
    """Match vulnerability patterns against decompiled functions.

    The core vulnerability detection primitive. Walks the Hex-Rays ctree and
    applies ~25 builtin patterns covering memory safety, format strings, integer
    issues, use-after-free, missing checks, command injection, and crypto misuse.

    Set addr='all' to scan every function in the binary. Use pattern= and
    categories= to narrow the search.
    """
    _load_builtin_patterns()

    # Build the list of patterns to apply
    registry = _PATTERN_REGISTRY
    selected_patterns: list[PatternConfig] = []

    cat_filter: set[str] | None = None
    if categories and categories.strip().lower() != "all":
        cat_filter = {c.strip().lower() for c in categories.split(",")}

    if pattern and pattern.strip().lower() != "all":
        names = {n.strip() for n in pattern.split(",")}
        for name in names:
            if name in registry:
                p = registry[name]
                if cat_filter is None or p["category"] in cat_filter:
                    selected_patterns.append(p)
    else:
        for p in registry.values():
            if cat_filter is None or p["category"] in cat_filter:
                selected_patterns.append(p)

    if not selected_patterns:
        return []

    results: list[CtreeMatchResult] = []

    if addr.strip().lower() == "all":
        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if func is None:
                continue
            func_name = ida_name.get_short_name(func.start_ea) or hex(func.start_ea)
            try:
                hf = ida_hexrays.hexrays_failure_t()
                cfunc = ida_hexrays.decompile(func.start_ea, hf)
                if cfunc is None:
                    continue
            except Exception:
                continue
            results.extend(_match_patterns_in_cfunc(cfunc, selected_patterns, func.start_ea, func_name))
    else:
        try:
            cfunc = _cfunc_from_addr(addr)
            func_ea = parse_address(addr)
            func_name = ida_name.get_short_name(func_ea) or addr
        except IDAError as e:
            return [{"addr": addr, "func_name": addr, "pattern_name": "error",
                     "category": "error", "severity": "low", "snippet": str(e),
                     "match_detail": str(e)}]
        results.extend(_match_patterns_in_cfunc(cfunc, selected_patterns, func_ea, func_name))

    return results[offset: offset + count] if count > 0 else results[offset:]


# ============================================================================
# Tool 3: ctree_callers_of
# ============================================================================

class _CallSiteFinder(ida_hexrays.ctree_visitor_t):
    """Find all calls to target function names and collect arg text + enclosing condition."""

    def __init__(self, targets: set[str]):
        super().__init__(ida_hexrays.CV_FAST)
        self.targets = targets
        self.sites: list[tuple[int, list[str]]] = []  # (call_ea, [arg_texts])

    def visit_expr(self, expr: "ida_hexrays.cexpr_t") -> int:
        if expr.op == ida_hexrays.cot_call:
            name = _get_call_name(expr)
            bare = name.lstrip("_")
            if name in self.targets or bare in self.targets:
                call_ea = expr.ea
                arg_texts = []
                for arg in expr.a:
                    try:
                        arg_texts.append(arg.dstr())
                    except Exception:
                        arg_texts.append("<arg>")
                self.sites.append((call_ea, arg_texts))
        return 0


def _collect_if_ea_ranges(cfunc: "ida_hexrays.cfunc_t") -> list[tuple[int, int, str]]:
    """Collect (min_ea, max_ea, condition_text) for every cit_if block."""
    class _EaCollector(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)
            self.eas: list[int] = []

        def visit_expr(self, expr: "ida_hexrays.cexpr_t") -> int:
            ea = getattr(expr, "ea", idaapi.BADADDR)
            if ea != idaapi.BADADDR:
                self.eas.append(ea)
            return 0

        def visit_insn(self, insn: "ida_hexrays.cinsn_t") -> int:
            ea = getattr(insn, "ea", idaapi.BADADDR)
            if ea != idaapi.BADADDR:
                self.eas.append(ea)
            return 0

    class _IfCollector(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)
            self.ranges: list[tuple[int, int, str]] = []

        def visit_insn(self, insn: "ida_hexrays.cinsn_t") -> int:
            if insn.op == ida_hexrays.cit_if:
                try:
                    cond_text = insn.cif.expr.dstr()
                except Exception:
                    cond_text = ""
                # Collect all ea values under this if-block to find range
                col = _EaCollector()
                col.apply_to_exprs(insn, None)
                # Also collect from then/else branches via the instruction visitor
                col2 = _EaCollector()
                col2.apply_to(insn, None)
                all_eas = [e for e in col2.eas if e != idaapi.BADADDR]
                if all_eas:
                    self.ranges.append((min(all_eas), max(all_eas), cond_text))
                elif insn.ea != idaapi.BADADDR:
                    self.ranges.append((insn.ea, insn.ea, cond_text))
            return 0

    col = _IfCollector()
    col.apply_to(cfunc.body, None)
    return col.ranges


def _find_enclosing_condition(cfunc: "ida_hexrays.cfunc_t", call_ea: int) -> str | None:
    """Walk the body looking for an if-statement that contains call_ea.

    Uses a two-pass approach: first collect all cit_if blocks with their ea
    ranges, then find the innermost one (smallest range) containing call_ea.
    """
    if call_ea == idaapi.BADADDR:
        return None

    ranges = _collect_if_ea_ranges(cfunc)
    best: tuple[int, str] | None = None  # (span, cond_text)
    for lo, hi, cond_text in ranges:
        if lo <= call_ea <= hi and cond_text:
            span = hi - lo
            if best is None or span < best[0]:
                best = (span, cond_text)

    return best[1] if best is not None else None


@tool
@idasync
def ctree_callers_of(
    target: Annotated[str, "Function name or address to find callers of"],
    include_args: Annotated[bool, "Include call argument text"] = True,
    include_condition: Annotated[bool, "Include enclosing if-condition text"] = True,
    offset: Annotated[int, "Pagination offset"] = 0,
    count: Annotated[int, "Max results to return"] = 100,
) -> list[CtreeCallerResult]:
    """Find all call sites to a function with full ctree context.

    Iterates all callers via cross-references, decompiles each caller function,
    and locates the call expression in the ctree to extract argument text and
    any enclosing conditional context.
    """
    # Resolve target EA and name
    try:
        target_ea = parse_address(target)
    except Exception as e:
        return [{"caller_addr": "0x0", "caller_name": "", "call_addr": "0x0",
                 "args": [], "enclosing_condition": str(e)}]

    target_name = ida_name.get_short_name(target_ea) or target
    targets: set[str] = {target_name, target_name.lstrip("_")}
    # Also include address-based matching later

    results: list[CtreeCallerResult] = []

    # Collect xrefs to target
    xref = idaapi.xrefblk_t()
    ok = xref.first_to(target_ea, idaapi.XREF_FAR)
    caller_eas: set[int] = set()
    while ok:
        func = ida_funcs.get_func(xref.frm)
        if func is not None:
            caller_eas.add(func.start_ea)
        ok = xref.next_to()

    for caller_ea in caller_eas:
        caller_name = ida_name.get_short_name(caller_ea) or hex(caller_ea)
        try:
            hf = ida_hexrays.hexrays_failure_t()
            cfunc = ida_hexrays.decompile(caller_ea, hf)
            if cfunc is None:
                continue
        except Exception:
            continue

        finder = _CallSiteFinder(targets)
        finder.apply_to(cfunc.body, None)

        for call_ea, arg_texts in finder.sites:
            entry: CtreeCallerResult = {
                "caller_addr": hex(caller_ea),
                "caller_name": caller_name,
                "call_addr": hex(call_ea) if call_ea != idaapi.BADADDR else hex(caller_ea),
                "args": arg_texts if include_args else [],
            }
            if include_condition:
                cond = _find_enclosing_condition(cfunc, call_ea)
                if cond:
                    entry["enclosing_condition"] = cond
            results.append(entry)

    return results[offset: offset + count] if count > 0 else results[offset:]


# ============================================================================
# Tool 4: ctree_vars
# ============================================================================

@tool
@idasync
def ctree_vars(
    addr: Annotated[str, "Function address or name"],
    filter: Annotated[str, "Substring filter applied to variable name or type"] = "",
) -> list[CtreeVarInfo]:
    """Extract variable information from a decompiled function.

    Returns all local variables and parameters from the Hex-Rays cfunc_t.lvars
    list, including type, size, and whether each is a parameter or stack variable.
    """
    try:
        cfunc = _cfunc_from_addr(addr)
    except IDAError as e:
        return [{"name": "error", "type": str(e), "is_param": False,
                 "is_stack": False, "size": 0, "source": "error"}]

    results: list[CtreeVarInfo] = []
    lvars = cfunc.get_lvars()
    for lvar in lvars:
        name = lvar.name or f"<unnamed_{lvar.idx}>"
        try:
            type_str = lvar.type().dstr()
        except Exception:
            type_str = "<unknown>"
        is_param = lvar.is_arg_var
        is_stack = lvar.is_stk_var()
        size = lvar.width
        source = "param" if is_param else ("stack" if is_stack else "register")

        if filter:
            fl = filter.lower()
            if fl not in name.lower() and fl not in type_str.lower():
                continue

        results.append({
            "name": name,
            "type": type_str,
            "is_param": is_param,
            "is_stack": is_stack,
            "size": size,
            "source": source,
        })

    return results
