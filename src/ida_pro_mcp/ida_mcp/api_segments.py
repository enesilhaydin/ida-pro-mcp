"""Segment API - list segments, cross-references, and exception handler enumeration."""

from typing import Annotated, NotRequired, TypedDict

import idaapi
import idautils
import ida_bytes
import ida_nalt
import ida_segment

from .rpc import tool
from .sync import idasync
from .utils import parse_address


class SegmentInfo(TypedDict):
    name: str
    start: str
    end: str
    size: int
    permissions: str
    type: str
    bitness: int
    is_loaded: bool


# ============================================================================
# Helpers
# ============================================================================

_SEGPERM_READ = getattr(idaapi, "SEGPERM_READ", 4)
_SEGPERM_WRITE = getattr(idaapi, "SEGPERM_WRITE", 2)
_SEGPERM_EXEC = getattr(idaapi, "SEGPERM_EXEC", 1)

_BITNESS_MAP = {0: 16, 1: 32, 2: 64}


def _seg_permissions(seg) -> str:
    perm = seg.perm
    r = "r" if (perm & _SEGPERM_READ) else "-"
    w = "w" if (perm & _SEGPERM_WRITE) else "-"
    x = "x" if (perm & _SEGPERM_EXEC) else "-"
    return r + w + x


def _seg_info(seg) -> SegmentInfo:
    name = ida_segment.get_segm_name(seg) or ""
    seg_class = ida_segment.get_segm_class(seg) or ""
    bitness = _BITNESS_MAP.get(seg.bitness, 32)
    is_loaded = bool(seg.is_loaded())
    return {
        "name": name,
        "start": hex(seg.start_ea),
        "end": hex(seg.end_ea),
        "size": seg.size(),
        "permissions": _seg_permissions(seg),
        "type": seg_class,
        "bitness": bitness,
        "is_loaded": is_loaded,
    }


def _get_all_segments() -> list:
    segs = []
    seg = ida_segment.get_first_seg()
    while seg is not None:
        segs.append(seg)
        seg = ida_segment.get_next_seg(seg.start_ea)
    return segs


def _filter_matches(info: SegmentInfo, filter_str: str) -> bool:
    """Return True if segment matches the filter (name substring or permission string)."""
    if not filter_str:
        return True
    f = filter_str.lower()
    # Permission filter: only contains r/w/x/- characters
    if all(c in "rwx-" for c in f):
        return f in info["permissions"]
    # Name filter
    return f in info["name"].lower()


# ============================================================================
# Tools
# ============================================================================


@tool
@idasync
def list_segments(
    filter: Annotated[
        str, "Name filter ('.text') or permission filter ('rwx', 'rw')"
    ] = "",
) -> list[SegmentInfo]:
    """List all binary segments with permissions and metadata."""
    results = []
    for seg in _get_all_segments():
        info = _seg_info(seg)
        if _filter_matches(info, filter):
            results.append(info)
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
    """Analyze cross-references between segments."""
    import idc

    count = min(count, 500)
    xref_type = xref_type.lower()

    # Build segment lookup: name -> (start, end) for iteration
    seg_map: dict[str, tuple[int, int]] = {}
    for seg in _get_all_segments():
        name = ida_segment.get_segm_name(seg) or ""
        seg_map[name] = (seg.start_ea, seg.end_ea)

    def _ea_to_seg_name(ea: int) -> str | None:
        seg = ida_segment.getseg(ea)
        if seg is None:
            return None
        return ida_segment.get_segm_name(seg) or None

    from_seg_lower = from_segment.lower()
    to_seg_lower = to_segment.lower()

    all_xrefs = []
    max_sample = 10000
    sampled = 0

    for seg_name, (seg_start, seg_end) in seg_map.items():
        if from_seg_lower != "all" and seg_name.lower() != from_seg_lower:
            continue

        for head in idautils.Heads(seg_start, seg_end):
            if sampled >= max_sample:
                break
            sampled += 1

            for xref in idautils.XrefsFrom(head, 0):
                to_ea = xref.to
                to_name = _ea_to_seg_name(to_ea)
                if to_name is None:
                    continue
                # Skip same-segment xrefs
                if to_name == seg_name:
                    continue
                # Filter by to_segment
                if to_seg_lower != "all" and to_name.lower() != to_seg_lower:
                    continue
                # Filter by xref type
                xtype = "code" if xref.iscode else "data"
                if xref_type != "all" and xtype != xref_type:
                    continue

                func_context = None
                fn = idaapi.get_func(head)
                if fn:
                    func_context = idaapi.get_name(fn.start_ea) or hex(fn.start_ea)

                entry: dict = {
                    "from_addr": hex(head),
                    "to_addr": hex(to_ea),
                    "from_segment": seg_name,
                    "to_segment": to_name,
                    "type": xtype,
                }
                if func_context:
                    entry["func_context"] = func_context
                all_xrefs.append(entry)

    total = len(all_xrefs)
    page = all_xrefs[offset: offset + count]

    # Summarise by direction (from_seg -> to_seg)
    by_direction: dict[str, int] = {}
    for x in all_xrefs:
        key = f"{x['from_segment']} -> {x['to_segment']}"
        by_direction[key] = by_direction.get(key, 0) + 1

    return {
        "xrefs": page,
        "summary": {
            "total": total,
            "by_direction": by_direction,
        },
    }


# ============================================================================
# Exception Handler Enumeration
# ============================================================================


class ExceptionHandlerItem(TypedDict, total=False):
    func_start: str
    func_end: str
    handler: str
    handler_name: str
    unwind_info: str
    format: str  # "pdata" | "eh_frame" | "unknown"


class ExceptionHandlersResult(TypedDict):
    handlers: list[ExceptionHandlerItem]
    count: int
    format: str
    warning: NotRequired[str]


def _read_dword(ea: int) -> int | None:
    """Read a 4-byte little-endian value, returning None if unloaded."""
    if not ida_bytes.is_loaded(ea):
        return None
    return ida_bytes.get_dword(ea)


def _read_qword(ea: int) -> int | None:
    if not ida_bytes.is_loaded(ea):
        return None
    return ida_bytes.get_qword(ea)


def _parse_pdata_x64(pdata_seg, image_base: int) -> list[ExceptionHandlerItem]:
    """Parse Windows x64 .pdata section into RUNTIME_FUNCTION entries."""
    handlers: list[ExceptionHandlerItem] = []
    ea = pdata_seg.start_ea
    end_ea = pdata_seg.end_ea

    while ea + 12 <= end_ea:
        begin_rva = _read_dword(ea)
        end_rva = _read_dword(ea + 4)
        unwind_rva = _read_dword(ea + 8)

        if begin_rva is None or end_rva is None or unwind_rva is None:
            break

        if begin_rva == 0:
            ea += 12
            continue

        func_start = image_base + begin_rva
        func_end = image_base + end_rva
        unwind_ea = image_base + (unwind_rva & ~3)  # mask off chain flag

        handler_name = idaapi.get_name(func_start) or ""

        item = ExceptionHandlerItem(
            func_start=hex(func_start),
            func_end=hex(func_end),
            handler=hex(unwind_ea),
            handler_name=handler_name,
            unwind_info=hex(unwind_ea),
            format="pdata",
        )
        handlers.append(item)
        ea += 12

    return handlers


def _parse_eh_frame(eh_frame_seg) -> list[ExceptionHandlerItem]:
    """Parse ELF .eh_frame section for CIE/FDE entries."""
    handlers: list[ExceptionHandlerItem] = []
    ea = eh_frame_seg.start_ea
    end_ea = eh_frame_seg.end_ea

    while ea + 8 <= end_ea:
        length = _read_dword(ea)
        if length is None or length == 0:
            break

        # CIE_id: 0 means CIE, non-zero means FDE
        cie_id = _read_dword(ea + 4)
        if cie_id is None:
            break

        entry_end = ea + 4 + length
        if entry_end > end_ea:
            break

        if cie_id != 0:
            # FDE: pc_begin is at ea+8 (relative or absolute depending on encoding)
            pc_begin_raw = _read_dword(ea + 8)
            if pc_begin_raw is not None:
                # For PC-relative encoding: pc_begin = (ea+8) + signed_offset
                pc_begin = (ea + 8 + pc_begin_raw) & 0xFFFFFFFFFFFFFFFF
                func_name = idaapi.get_name(pc_begin) or ""
                handlers.append(ExceptionHandlerItem(
                    func_start=hex(pc_begin),
                    func_end=hex(pc_begin),  # end requires parsing pc_range
                    handler=hex(ea),
                    handler_name=func_name,
                    unwind_info=hex(ea),
                    format="eh_frame",
                ))

        ea = entry_end

    return handlers


def _get_image_base() -> int:
    """Get the image base from the IDB."""
    try:
        import ida_ida
        return ida_ida.inf_get_min_ea() & ~0xFFFF
    except Exception:
        return 0


@tool
@idasync
def exception_handlers(
    func: Annotated[
        str | None,
        "Function address/name to filter to, or null/empty to return all handlers",
    ] = None,
) -> ExceptionHandlersResult:
    """Enumerate SEH/EH exception handler frames in the binary.

    For Windows PE binaries: parses the .pdata section (x64 RUNTIME_FUNCTION
    array) to enumerate structured exception handlers.

    For ELF binaries: parses the .eh_frame section for DWARF CFI FDE entries.

    When 'func' is specified, filters results to the function covering that
    address. When null/empty, returns all handlers found.

    Returns list of {func_start, func_end, handler, handler_name, unwind_info,
    format} dicts. Returns an empty list with a warning if no EH data is found.
    """
    import idc

    handlers: list[ExceptionHandlerItem] = []
    fmt = "unknown"
    warning: str | None = None

    # Find .pdata (Windows PE x64)
    pdata_seg = ida_segment.get_segm_by_name(".pdata")
    eh_frame_seg = ida_segment.get_segm_by_name(".eh_frame")

    if pdata_seg is not None:
        fmt = "pdata"
        image_base = _get_image_base()
        handlers = _parse_pdata_x64(pdata_seg, image_base)
    elif eh_frame_seg is not None:
        fmt = "eh_frame"
        handlers = _parse_eh_frame(eh_frame_seg)
    else:
        # Try alternate names
        for alt in (".xdata", ".pdata$x", "__eh_frame", ".gcc_except_table"):
            seg = ida_segment.get_segm_by_name(alt)
            if seg is not None:
                if alt in (".xdata", ".pdata$x"):
                    fmt = "pdata"
                    image_base = _get_image_base()
                    handlers = _parse_pdata_x64(seg, image_base)
                else:
                    fmt = "eh_frame"
                    handlers = _parse_eh_frame(seg)
                break

        if not handlers:
            warning = (
                "No .pdata or .eh_frame section found. "
                "This binary may not have structured exception handling data, "
                "or EH info may be in a non-standard location."
            )

    # Filter by function if requested
    if func and func.strip():
        try:
            filter_ea = parse_address(func.strip())
            fn = idaapi.get_func(filter_ea)
            if fn:
                fn_start_hex = hex(fn.start_ea)
                handlers = [h for h in handlers if h.get("func_start") == fn_start_hex]
            else:
                # Filter by address range
                filter_hex = hex(filter_ea)
                handlers = [h for h in handlers if h.get("func_start") == filter_hex]
        except Exception:
            pass

    result = ExceptionHandlersResult(handlers=handlers, count=len(handlers), format=fmt)
    if warning:
        result["warning"] = warning
    return result
