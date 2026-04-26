"""Microcode def-use chain analysis tools.

Provides 5 MCP tools:
- mcode_defuse: Extract def-use chains for variables in microcode IR
- mcode_source: Trace value origin backward through def-use chains
- mcode_inspect: Dump microcode IR blocks with pagination and filtering
- microcode_insert_assertion: Inject a constant-value assertion into microcode (IDA 9.3+)
- microcode_delete_insn: Delete a microinstruction from a block (IDA 9.3+)
"""

from typing import Annotated, NotRequired, TypedDict
import ida_hexrays
import idaapi

from .rpc import tool
from .sync import idasync, IDAError, ida_major, ida_minor
from .utils import parse_address


def _require_ida_93():
    """Raise IDAError if IDA version < 9.3 (microcode manipulation requires 9.3+)."""
    if ida_major < 9 or (ida_major == 9 and ida_minor < 3):
        raise IDAError(
            f"This tool requires IDA Pro 9.3+. "
            f"Current version: {ida_major}.{ida_minor}"
        )


# IDA 9.x renamed area_t → range_t; support both
_range_t = getattr(idaapi, "range_t", None) or getattr(idaapi, "area_t", None)

# mop_S (stack variable operand) value is 5 in the IDA SDK; use getattr for safety
_MOP_S = getattr(ida_hexrays, "mop_S", 5)


# ============================================================================
# Maturity level map
# ============================================================================

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


# ============================================================================
# TypedDicts
# ============================================================================


class DefUseSite(TypedDict):
    addr: str
    text: str


class DefUseResult(TypedDict):
    var_name: str
    definitions: list[DefUseSite]
    uses: list[DefUseSite]
    error: NotRequired[str]


class McodeSourceResult(TypedDict):
    var: str
    origin_type: str  # "param" | "global" | "const" | "retval" | "unknown"
    origin_detail: str
    chain: list[dict]
    error: NotRequired[str]


class McodeInsnInfo(TypedDict):
    addr: str
    opcode: int
    text: str


class McodeBlockInfo(TypedDict):
    index: int
    start_addr: str
    instructions: list[McodeInsnInfo]
    succs: list[int]
    preds: list[int]


class McodeInspectResult(TypedDict):
    maturity: str
    block_count: int
    insn_count: int
    blocks: list[McodeBlockInfo]
    error: NotRequired[str]


# ============================================================================
# Internal helpers
# ============================================================================


def _resolve_maturity(maturity: str) -> int:
    """Resolve maturity string to integer constant, raising IDAError on invalid."""
    if maturity not in _MATURITY_MAP:
        valid = ", ".join(_MATURITY_MAP.keys())
        raise IDAError(f"Unknown maturity {maturity!r}. Valid values: {valid}")
    return _MATURITY_MAP[maturity]


def _get_mba(ea: int, maturity: int) -> "ida_hexrays.mba_t":
    """Generate microcode for the function containing ea at the given maturity."""
    pfn = idaapi.get_func(ea)
    if pfn is None:
        raise IDAError(f"No function at address 0x{ea:x}")
    mbr = ida_hexrays.mba_ranges_t()
    mbr.ranges.push_back(_range_t(pfn.start_ea, pfn.end_ea))
    hf = ida_hexrays.hexrays_failure_t()
    ml = ida_hexrays.mlist_t()
    mba = ida_hexrays.gen_microcode(
        mbr, hf, ml, ida_hexrays.DECOMP_WARNINGS, maturity
    )
    if mba is None:
        raise IDAError(f"Microcode generation failed: {hf.str}")
    return mba


def _mop_key(mop: "ida_hexrays.mop_t") -> str:
    """Return a stable string key for an mop_t operand."""
    try:
        return mop.dstr()
    except Exception:
        return ""


def _insn_text(insn: "ida_hexrays.minsn_t") -> str:
    try:
        return insn.dstr()
    except Exception:
        return ""


def _parse_block_filter(block_filter: str, block_count: int) -> set[int] | None:
    """Parse '3' or '0-5' filter into a set of block indices, or None for all."""
    if not block_filter.strip():
        return None
    part = block_filter.strip()
    try:
        if "-" in part:
            lo_s, hi_s = part.split("-", 1)
            lo, hi = int(lo_s.strip()), int(hi_s.strip())
            return set(range(max(0, lo), min(block_count, hi + 1)))
        else:
            idx = int(part)
            if 0 <= idx < block_count:
                return {idx}
            return set()
    except ValueError:
        raise IDAError(
            f"Invalid block_filter {block_filter!r}: expected an integer ('3') "
            "or inclusive range ('0-5')"
        )


# ============================================================================
# Tool: mcode_defuse
# ============================================================================


@tool
@idasync
def mcode_defuse(
    func_addr: Annotated[str, "Function address (e.g. 0x401000) or name"],
    var: Annotated[
        str,
        "Variable name to filter on, or 'all' to return chains for every operand",
    ] = "all",
    maturity: Annotated[
        str,
        "Microcode maturity level: MMAT_GENERATED | MMAT_PREOPTIMIZED | MMAT_LOCOPT"
        " | MMAT_CALLS | MMAT_GLBOPT1 | MMAT_GLBOPT2 | MMAT_GLBOPT3 | MMAT_LVARS",
    ] = "MMAT_GLBOPT1",
) -> list[DefUseResult]:
    """Extract def-use chains from microcode IR for variables in a function.

    Generates microcode at the requested maturity level and walks every
    mblock_t / minsn_t to collect definition sites (destination operand) and
    use sites (left / right source operands) for each distinct mop_t key.

    Returns one DefUseResult per variable; filtered to the requested name when
    var != 'all'.
    """
    ea = parse_address(func_addr)
    mat = _resolve_maturity(maturity)
    mba = _get_mba(ea, mat)

    # defs[key] = list of (ea, text), uses[key] = list of (ea, text)
    defs: dict[str, list[DefUseSite]] = {}
    uses: dict[str, list[DefUseSite]] = {}

    for blk_idx in range(mba.qty):
        blk = mba.get_mblock(blk_idx)
        insn = blk.head
        while insn is not None:
            itext = _insn_text(insn)
            addr_str = f"0x{insn.ea:x}"

            # destination = definition
            if insn.d is not None and insn.d.t != ida_hexrays.mop_z:
                key = _mop_key(insn.d)
                if key:
                    defs.setdefault(key, []).append(
                        DefUseSite(addr=addr_str, text=itext)
                    )

            # left source = use
            if insn.l is not None and insn.l.t != ida_hexrays.mop_z:
                key = _mop_key(insn.l)
                if key:
                    uses.setdefault(key, []).append(
                        DefUseSite(addr=addr_str, text=itext)
                    )

            # right source = use
            if insn.r is not None and insn.r.t != ida_hexrays.mop_z:
                key = _mop_key(insn.r)
                if key:
                    uses.setdefault(key, []).append(
                        DefUseSite(addr=addr_str, text=itext)
                    )

            insn = insn.next

    all_keys = set(defs.keys()) | set(uses.keys())

    results: list[DefUseResult] = []
    for key in sorted(all_keys):
        if var != "all" and key != var:
            continue
        results.append(
            DefUseResult(
                var_name=key,
                definitions=defs.get(key, []),
                uses=uses.get(key, []),
            )
        )

    return results


# ============================================================================
# Tool: mcode_source
# ============================================================================


def _classify_origin(mop: "ida_hexrays.mop_t") -> tuple[str, str]:
    """Return (origin_type, origin_detail) for an mop_t."""
    t = mop.t
    if t == ida_hexrays.mop_n:
        return "const", f"0x{mop.nnn.value:x}" if hasattr(mop, "nnn") else "const"
    if t == ida_hexrays.mop_a:
        try:
            detail = f"0x{mop.a.off:x}"
        except Exception:
            detail = mop.dstr()
        return "global", detail
    if t == ida_hexrays.mop_r:
        return "param", mop.dstr()
    if t == _MOP_S:
        return "local", mop.dstr()
    if t == ida_hexrays.mop_d:
        return "retval", mop.dstr()
    return "unknown", mop.dstr()


@tool
@idasync
def mcode_source(
    func_addr: Annotated[str, "Function address (e.g. 0x401000) or name"],
    var: Annotated[str, "Variable name (mop_t key) to trace backward"],
    max_depth: Annotated[int, "Maximum backward-trace depth (1-20)"] = 10,
    maturity: Annotated[
        str,
        "Microcode maturity level: MMAT_GENERATED | MMAT_PREOPTIMIZED | MMAT_LOCOPT"
        " | MMAT_CALLS | MMAT_GLBOPT1 | MMAT_GLBOPT2 | MMAT_GLBOPT3 | MMAT_LVARS",
    ] = "MMAT_GLBOPT1",
) -> McodeSourceResult:
    """Trace the value origin of a microcode variable backward through def-use chains.

    Starting from the first definition of 'var', follows the source operand
    recursively up to max_depth steps, classifying the ultimate origin as one of:
    const, global, param, retval, or unknown.

    Limitations:
    - First-definition semantics: only the first assignment to each variable key
      in textual block order is considered; later redefinitions are ignored.
    - Single-path tracing: at each step only the left source operand is followed
      (right operand used as fallback). Phi-nodes and multi-source merges are not
      traversed; the reported chain reflects one data-flow path, not all paths.

    Returns the full trace chain and origin classification.
    """
    ea = parse_address(func_addr)
    max_depth = min(max(1, max_depth), 20)
    mat = _resolve_maturity(maturity)
    mba = _get_mba(ea, mat)

    # Build a map: dest_key -> (insn, left_mop, right_mop) for first definition
    def_map: dict[str, tuple] = {}
    for blk_idx in range(mba.qty):
        blk = mba.get_mblock(blk_idx)
        insn = blk.head
        while insn is not None:
            if insn.d is not None and insn.d.t != ida_hexrays.mop_z:
                key = _mop_key(insn.d)
                if key and key not in def_map:
                    def_map[key] = insn
            insn = insn.next

    chain: list[dict] = []
    current_key = var
    origin_type = "unknown"
    origin_detail = var

    if current_key not in def_map:
        return McodeSourceResult(
            var=var,
            origin_type="unknown",
            origin_detail=var,
            chain=[],
            error=f"Variable {var!r} not found in microcode definitions",
        )

    visited: set[str] = set()
    for step in range(max_depth):
        if current_key in visited:
            break
        visited.add(current_key)

        insn = def_map.get(current_key)
        if insn is None:
            break

        chain.append(
            {
                "addr": f"0x{insn.ea:x}",
                "text": _insn_text(insn),
                "step": step,
            }
        )

        # Pick the primary source operand (prefer left, fall back to right)
        src_mop = None
        if insn.l is not None and insn.l.t != ida_hexrays.mop_z:
            src_mop = insn.l
        elif insn.r is not None and insn.r.t != ida_hexrays.mop_z:
            src_mop = insn.r

        if src_mop is None:
            origin_type = "unknown"
            origin_detail = current_key
            break

        origin_type, origin_detail = _classify_origin(src_mop)

        if origin_type != "retval":
            # Reached a leaf — const, global, param
            break

        # retval = result of another insn; keep tracing
        next_key = _mop_key(src_mop)
        if not next_key or next_key == current_key:
            break
        current_key = next_key

    return McodeSourceResult(
        var=var,
        origin_type=origin_type,
        origin_detail=origin_detail,
        chain=chain,
    )


# ============================================================================
# Tool: mcode_inspect
# ============================================================================


@tool
@idasync
def mcode_inspect(
    func_addr: Annotated[str, "Function address (e.g. 0x401000) or name"],
    maturity: Annotated[
        str,
        "Microcode maturity level: MMAT_GENERATED | MMAT_PREOPTIMIZED | MMAT_LOCOPT"
        " | MMAT_CALLS | MMAT_GLBOPT1 | MMAT_GLBOPT2 | MMAT_GLBOPT3 | MMAT_LVARS",
    ] = "MMAT_GLBOPT1",
    block_filter: Annotated[
        str,
        "Block index ('3') or inclusive range ('0-5') to restrict output; "
        "empty string means all blocks",
    ] = "",
    offset: Annotated[int, "Pagination offset — skip this many instructions"] = 0,
    count: Annotated[int, "Maximum number of instructions to return (max 500)"] = 200,
) -> McodeInspectResult:
    """Dump microcode IR blocks for a function with optional filtering and pagination.

    Generates microcode at the requested maturity level and returns the basic
    block graph including instructions (address, opcode, display text),
    successor/predecessor block indices.

    Use block_filter to focus on specific blocks; use offset/count to paginate
    over large functions.
    """
    ea = parse_address(func_addr)
    mat = _resolve_maturity(maturity)
    count = min(max(1, count), 500)
    offset = max(0, offset)
    mba = _get_mba(ea, mat)

    block_count = mba.qty
    allowed_blocks = _parse_block_filter(block_filter, block_count)

    # Collect all instructions across (filtered) blocks with global ordering
    # for pagination purposes
    all_insns: list[tuple[int, "ida_hexrays.minsn_t"]] = []  # (blk_idx, insn)
    for blk_idx in range(block_count):
        if allowed_blocks is not None and blk_idx not in allowed_blocks:
            continue
        blk = mba.get_mblock(blk_idx)
        insn = blk.head
        while insn is not None:
            all_insns.append((blk_idx, insn))
            insn = insn.next

    total_insns = len(all_insns)
    paged = all_insns[offset: offset + count]

    # Group paged instructions back by block for structured output
    block_insns: dict[int, list[McodeInsnInfo]] = {}
    for blk_idx, insn in paged:
        block_insns.setdefault(blk_idx, []).append(
            McodeInsnInfo(
                addr=f"0x{insn.ea:x}",
                opcode=insn.opcode,
                text=_insn_text(insn),
            )
        )

    blocks: list[McodeBlockInfo] = []
    for blk_idx in sorted(block_insns.keys()):
        blk = mba.get_mblock(blk_idx)
        succs = [blk.succ(i) for i in range(blk.nsucc())]
        preds = [blk.pred(i) for i in range(blk.npred())]
        blocks.append(
            McodeBlockInfo(
                index=blk_idx,
                start_addr=f"0x{blk.start:x}",
                instructions=block_insns[blk_idx],
                succs=succs,
                preds=preds,
            )
        )

    return McodeInspectResult(
        maturity=maturity,
        block_count=block_count,
        insn_count=total_insns,
        blocks=blocks,
    )


# ============================================================================
# Group 5: microcode_insert_assertion / microcode_delete_insn (IDA 9.3+)
# ============================================================================


class AssertionResult(TypedDict, total=False):
    func: str
    addr: str
    reg: str
    value: int
    inserted: bool
    error: str


class DeleteInsnResult(TypedDict, total=False):
    func: str
    addr: str
    deleted: bool
    text: str
    error: str


@tool
@idasync
def microcode_insert_assertion(
    func: Annotated[str, "Function address or name (e.g. 0x401000 or main)"],
    addr: Annotated[str, "Address within the function where assertion is inserted"],
    reg: Annotated[str, "Register name to constrain (e.g. 'eax', 'rdi')"],
    value: Annotated[int, "Constant value to assert for the register"],
) -> AssertionResult:
    """Inject a constant-value microcode assertion for a register at an address (IDA 9.3+).

    Inserts a 'mov #value, reg' microinstruction into the microcode block
    containing 'addr'. This constrains the decompiler's value analysis and can
    steer decompilation past obfuscation or help resolve indirect control flow.

    Requires IDA Pro 9.3+ (mblock_t.insert_into_block API).
    The function is re-decompiled after insertion to commit the change.
    """
    _require_ida_93()

    try:
        fn_ea = parse_address(func)
        fn = idaapi.get_func(fn_ea)
        if fn is None:
            return AssertionResult(func=func, addr=addr, reg=reg, value=value,
                                   inserted=False, error="Function not found")

        target_ea = parse_address(addr)
        mat = _MATURITY_MAP["MMAT_GLBOPT1"]
        mba = _get_mba(fn_ea, mat)

        # Find the mblock containing target_ea
        target_block = None
        target_insn = None
        for blk_idx in range(mba.qty):
            blk = mba.get_mblock(blk_idx)
            if blk.start <= target_ea < blk.end:
                target_block = blk
                # Find the instruction at or after target_ea
                insn = blk.head
                while insn is not None:
                    if insn.ea >= target_ea:
                        target_insn = insn
                        break
                    insn = insn.next
                break

        if target_block is None:
            return AssertionResult(func=func, addr=addr, reg=reg, value=value,
                                   inserted=False,
                                   error=f"Address {addr} not found in function microcode")

        # Build assertion: mov #value, reg
        # minsn_t with opcode m_mov, left=const operand, dest=reg operand
        new_insn = ida_hexrays.minsn_t(target_ea)
        new_insn.opcode = ida_hexrays.m_mov

        # Set left operand to constant value
        new_insn.l.make_number(value, 8, target_ea)

        # Set destination operand to register
        # Try to resolve register number from name
        reg_num = idaapi.str2reg(reg)
        if reg_num < 0:
            return AssertionResult(func=func, addr=addr, reg=reg, value=value,
                                   inserted=False,
                                   error=f"Unknown register: {reg!r}")
        new_insn.d.make_reg(reg_num, 8)

        # Insert before target_insn (or at block end if not found)
        if target_insn is not None:
            target_block.insert_into_block(new_insn, target_insn.prev)
        else:
            target_block.insert_into_block(new_insn, target_block.tail)

        mba.verify(True)

        return AssertionResult(func=func, addr=addr, reg=reg, value=value, inserted=True)

    except IDAError:
        raise
    except Exception as e:
        return AssertionResult(func=func, addr=addr, reg=reg, value=value,
                               inserted=False, error=str(e))


@tool
@idasync
def microcode_delete_insn(
    func: Annotated[str, "Function address or name (e.g. 0x401000 or main)"],
    addr: Annotated[str, "Address of the microinstruction to delete"],
) -> DeleteInsnResult:
    """Delete a microinstruction from its containing block (IDA 9.3+).

    Finds the first microinstruction at 'addr' within the function's microcode
    and removes it using mblock_t.remove_from_block(). This is useful for
    removing obfuscation instructions that confuse decompilation.

    Requires IDA Pro 9.3+ (mblock_t.remove_from_block API).
    """
    _require_ida_93()

    try:
        fn_ea = parse_address(func)
        fn = idaapi.get_func(fn_ea)
        if fn is None:
            return DeleteInsnResult(func=func, addr=addr, deleted=False,
                                    error="Function not found")

        target_ea = parse_address(addr)
        mat = _MATURITY_MAP["MMAT_GLBOPT1"]
        mba = _get_mba(fn_ea, mat)

        for blk_idx in range(mba.qty):
            blk = mba.get_mblock(blk_idx)
            insn = blk.head
            while insn is not None:
                if insn.ea == target_ea:
                    text = _insn_text(insn)
                    blk.remove_from_block(insn)
                    mba.verify(True)
                    return DeleteInsnResult(
                        func=func, addr=addr, deleted=True, text=text
                    )
                insn = insn.next

        return DeleteInsnResult(
            func=func, addr=addr, deleted=False,
            error=f"No microinstruction found at {addr}"
        )

    except IDAError:
        raise
    except Exception as e:
        return DeleteInsnResult(func=func, addr=addr, deleted=False, error=str(e))
