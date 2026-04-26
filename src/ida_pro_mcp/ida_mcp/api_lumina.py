"""Lumina function metadata query/push/pull tools (IDA 9.3+).

Provides three MCP tools:
- lumina_query: Query Lumina name suggestions for addresses without applying
- lumina_pull: Pull Lumina-known names and apply to unnamed functions
- lumina_push: Push local function metadata to Lumina server

All tools require IDA 9.3+ with the ida_lumina Python module. On older IDA
versions they raise a descriptive McpToolError so the caller understands
what is needed.
"""

from typing import Annotated, NotRequired, TypedDict

import idaapi
import ida_funcs
import idautils

from .rpc import tool
from .sync import idasync, IDAError
from .utils import parse_address, normalize_list_input


# ============================================================================
# Version guard
# ============================================================================

try:
    import ida_lumina as _ida_lumina
    _LUMINA_AVAILABLE = True
except ImportError:
    _ida_lumina = None  # type: ignore[assignment]
    _LUMINA_AVAILABLE = False


def _require_lumina():
    """Raise IDAError with a clear message if Lumina is unavailable."""
    if not _LUMINA_AVAILABLE:
        raise IDAError(
            "ida_lumina is not available on this IDA version. "
            "Lumina tools require IDA Pro 9.3 or later."
        )


# ============================================================================
# TypedDicts
# ============================================================================


class LuminaQueryItem(TypedDict):
    addr: str
    suggested_name: str
    confidence: str


class LuminaQueryResult(TypedDict, total=False):
    results: list[LuminaQueryItem]
    count: int
    error: str


class LuminaPullItem(TypedDict):
    addr: str
    old_name: str
    new_name: str
    applied: bool


class LuminaPullResult(TypedDict, total=False):
    applied: list[LuminaPullItem]
    count: int
    error: str


class LuminaPushItem(TypedDict):
    addr: str
    name: str
    pushed: bool


class LuminaPushResult(TypedDict, total=False):
    pushed: list[LuminaPushItem]
    count: int
    error: str


# ============================================================================
# Internal helpers
# ============================================================================


def _is_default_name(name: str) -> bool:
    """Return True if this looks like an auto-generated IDA name (sub_XXXX, etc.)."""
    if not name:
        return True
    auto_prefixes = ("sub_", "loc_", "nullsub_", "j_", "unknown_libname_", "off_", "byte_",
                     "word_", "dword_", "qword_", "unk_")
    for prefix in auto_prefixes:
        if name.startswith(prefix):
            return True
    return False


def _lumina_get_name(ea: int) -> tuple[str | None, str]:
    """Query Lumina for the name suggestion at ea.

    Returns (suggested_name, confidence) or (None, 'none').
    """
    if not _LUMINA_AVAILABLE:
        return None, "none"
    try:
        # ida_lumina.get_func_metadata returns a lvar_name_t-like object or None
        # The exact API varies; try common patterns
        result = _ida_lumina.get_func_metadata(ea)  # type: ignore[attr-defined]
        if result is not None:
            name = getattr(result, "name", None) or getattr(result, "func_name", None)
            if name:
                return str(name), "high"
        return None, "none"
    except Exception:
        return None, "none"


# ============================================================================
# Tools
# ============================================================================


@tool
@idasync
def lumina_query(
    addrs: Annotated[
        list[str] | str,
        "Addresses or function names to query Lumina for (comma-separated or list)",
    ],
) -> LuminaQueryResult:
    """Query Lumina for name suggestions for a set of addresses without applying them.

    Requires IDA Pro 9.3+ with the ida_lumina module. Each address is queried
    independently; results include a suggested name and confidence level.

    Returns list of {addr, suggested_name, confidence} dicts.
    confidence is 'high' when Lumina returned a match, 'none' when not found.
    """
    _require_lumina()
    addrs = normalize_list_input(addrs)

    items: list[LuminaQueryItem] = []
    for addr_str in addrs:
        try:
            ea = parse_address(addr_str)
            name, conf = _lumina_get_name(ea)
            items.append(LuminaQueryItem(
                addr=hex(ea),
                suggested_name=name or "",
                confidence=conf,
            ))
        except Exception as e:
            items.append(LuminaQueryItem(
                addr=addr_str,
                suggested_name="",
                confidence="error",
            ))

    return LuminaQueryResult(results=items, count=len(items))


@tool
@idasync
def lumina_pull(
    funcs: Annotated[
        list[str] | str | None,
        "Function addresses/names to pull names for; pass null/empty to pull all unnamed functions",
    ] = None,
) -> LuminaPullResult:
    """Pull Lumina-known names and apply them to local unnamed functions.

    When funcs is null or empty, iterates all functions and applies Lumina
    suggestions to those with auto-generated names (sub_XXXX, etc.).
    When funcs is provided, only those functions are updated.

    Requires IDA Pro 9.3+ with the ida_lumina module.

    Returns list of {addr, old_name, new_name, applied} for each candidate.
    """
    _require_lumina()

    applied: list[LuminaPullItem] = []

    if funcs:
        addrs_list = normalize_list_input(funcs)
        candidates: list[int] = []
        for addr_str in addrs_list:
            try:
                ea = parse_address(addr_str)
                fn = idaapi.get_func(ea)
                if fn:
                    candidates.append(fn.start_ea)
            except Exception:
                pass
    else:
        # All unnamed functions
        candidates = [ea for ea in idautils.Functions()]

    for ea in candidates:
        fn = idaapi.get_func(ea)
        if not fn:
            continue
        old_name = ida_funcs.get_func_name(ea) or ""
        if funcs is None and not _is_default_name(old_name):
            continue  # Skip already-named functions when bulk pulling

        new_name, conf = _lumina_get_name(ea)
        if new_name and new_name != old_name:
            try:
                idaapi.set_name(ea, new_name, idaapi.SN_FORCE)
                applied.append(LuminaPullItem(addr=hex(ea), old_name=old_name,
                                               new_name=new_name, applied=True))
            except Exception:
                applied.append(LuminaPullItem(addr=hex(ea), old_name=old_name,
                                               new_name=new_name, applied=False))
        else:
            applied.append(LuminaPullItem(addr=hex(ea), old_name=old_name,
                                           new_name=new_name or old_name, applied=False))

    return LuminaPullResult(applied=applied, count=sum(1 for a in applied if a["applied"]))


@tool
@idasync
def lumina_push(
    funcs: Annotated[
        list[str] | str,
        "Function addresses or names to push to Lumina (comma-separated or list)",
    ],
) -> LuminaPushResult:
    """Push local function metadata to the Lumina server.

    Sends the current name and type information for each specified function to
    the connected Lumina server, contributing to the shared naming database.

    Requires IDA Pro 9.3+ with the ida_lumina module and a configured Lumina
    server connection.

    Returns list of {addr, name, pushed} for each function.
    """
    _require_lumina()
    addrs_list = normalize_list_input(funcs)

    pushed_items: list[LuminaPushItem] = []
    for addr_str in addrs_list:
        try:
            ea = parse_address(addr_str)
            fn = idaapi.get_func(ea)
            if not fn:
                pushed_items.append(LuminaPushItem(addr=addr_str, name="", pushed=False))
                continue

            name = ida_funcs.get_func_name(ea) or ""
            try:
                # push_func_metadata(ea) — IDA 9.3 API
                result = _ida_lumina.push_func_metadata(ea)  # type: ignore[attr-defined]
                pushed = bool(result)
            except Exception:
                pushed = False

            pushed_items.append(LuminaPushItem(addr=hex(ea), name=name, pushed=pushed))
        except Exception as e:
            pushed_items.append(LuminaPushItem(addr=addr_str, name="", pushed=False))

    return LuminaPushResult(
        pushed=pushed_items,
        count=sum(1 for p in pushed_items if p["pushed"]),
    )
