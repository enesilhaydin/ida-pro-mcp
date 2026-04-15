"""Segment API - list segments and analyze cross-references between segments."""

from typing import Annotated, NotRequired, TypedDict

import idaapi
import idautils
import ida_segment

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
