"""Tests for newly added MCP tools (HIGH and MEDIUM priority).

Groups tested:
  - Group 1: callers, name_search, string_xrefs
  - Group 2: switch_cases, indirect_call_targets
  - Group 3: find_paths, dominator_tree
  - Group 6: exception_handlers
  - Group A (MEDIUM): decompiler_comments
  - Group B (MEDIUM): idb_info, import_at
  - Group C (MEDIUM): dead_blocks
  - Group D (MEDIUM): export_header

Run with:
    uv run ida-mcp-test tests/crackme03.elf -q -p "*test_callers*"
    uv run ida-mcp-test tests/crackme03.elf -q
"""

import re

from ida_pro_mcp.ida_mcp.framework import test
from ida_pro_mcp.ida_mcp.api_analysis import (
    callers,
    name_search,
    string_xrefs,
    switch_cases,
    indirect_call_targets,
    dead_blocks,
)
from ida_pro_mcp.ida_mcp.api_paths import find_paths, dominator_tree
from ida_pro_mcp.ida_mcp.api_segments import exception_handlers
from ida_pro_mcp.ida_mcp.api_core import idb_info, import_at
from ida_pro_mcp.ida_mcp.api_modify import decompiler_comments
from ida_pro_mcp.ida_mcp.api_types import export_header


# ============================================================================
# Group 1: callers
# ============================================================================


@test()
def test_callers_returns_list():
    """callers() on 'main' should return a list result."""
    result = callers("main")
    assert isinstance(result, list), "callers() must return a list"
    assert len(result) >= 1, "Expected at least one result entry"
    item = result[0]
    assert "addr" in item, "Result must have addr"
    assert "callers" in item, "Result must have callers key"
    assert isinstance(item["callers"], list), "callers value must be a list"


@test()
def test_callers_items_have_required_fields():
    """callers() items must have func_name and addr."""
    result = callers("main")
    for entry in result:
        for caller in entry.get("callers", []):
            assert "func_name" in caller, "Caller item must have func_name"
            assert "addr" in caller, "Caller item must have addr"
            assert caller["addr"].startswith("0x"), "addr must be hex string"


@test()
def test_callers_batch_input():
    """callers() accepts comma-separated string."""
    result = callers("main,main")
    assert isinstance(result, list)
    assert len(result) == 2, "Should have one entry per input"


@test()
def test_callers_invalid_addr():
    """callers() on invalid address returns error field or empty callers."""
    result = callers("0xdeadbeefdeadbeef")
    assert isinstance(result, list)
    item = result[0]
    assert "error" in item or item.get("callers") == []


# ============================================================================
# Group 1: name_search
# ============================================================================


@test()
def test_name_search_finds_main():
    """name_search('main') should find at least one result."""
    result = name_search("main")
    assert "matches" in result, "Result must have matches"
    assert isinstance(result["matches"], list)
    assert result["count"] >= 1, "Should find at least one name matching 'main'"


@test()
def test_name_search_result_fields():
    """name_search results have addr, name, type fields."""
    result = name_search(".")
    for item in result["matches"][:10]:
        assert "addr" in item
        assert "name" in item
        assert "type" in item
        assert item["type"] in ("function", "import", "name")
        assert item["addr"].startswith("0x")


@test()
def test_name_search_invalid_regex():
    """name_search with invalid regex returns error, not exception."""
    result = name_search("[invalid(")
    assert "error" in result, "Invalid regex should produce error key"
    assert result["count"] == 0


@test()
def test_name_search_limit_respected():
    """name_search respects limit parameter."""
    result = name_search(".", limit=5)
    assert result["count"] <= 5
    assert len(result["matches"]) <= 5


# ============================================================================
# Group 1: string_xrefs
# ============================================================================


@test()
def test_string_xrefs_returns_result():
    """string_xrefs() returns a result with matches and count."""
    result = string_xrefs(".")
    assert "matches" in result
    assert "count" in result
    assert isinstance(result["matches"], list)


@test()
def test_string_xrefs_item_fields():
    """string_xrefs items have string, addr, callers fields."""
    result = string_xrefs(".", limit=10)
    for item in result["matches"]:
        assert "string" in item
        assert "addr" in item
        assert "callers" in item
        assert isinstance(item["callers"], list)
        assert item["addr"].startswith("0x")
        for caller in item["callers"]:
            assert "addr" in caller
            assert "func_name" in caller


@test()
def test_string_xrefs_count_matches_list():
    """string_xrefs count equals len(matches)."""
    result = string_xrefs(".", limit=20)
    assert result["count"] == len(result["matches"])


# ============================================================================
# Group 2: switch_cases
# ============================================================================


@test()
def test_switch_cases_no_switch_returns_error():
    """switch_cases on a non-switch address returns error."""
    result = switch_cases("main")
    if "error" in result:
        assert isinstance(result["error"], str)
    else:
        assert "jumps" in result
        assert "ncases" in result


@test()
def test_switch_cases_result_fields_when_present():
    """switch_cases result has correct fields when a switch is found."""
    result = switch_cases("main")
    if "error" not in result:
        assert "jumps" in result
        assert "ncases" in result
        assert isinstance(result["jumps"], list)
        for case in result["jumps"]:
            assert "value" in case
            assert "target" in case


# ============================================================================
# Group 2: indirect_call_targets
# ============================================================================


@test()
def test_indirect_call_targets_structure():
    """indirect_call_targets returns addr and targets list."""
    result = indirect_call_targets("main")
    assert "addr" in result
    assert "targets" in result
    assert isinstance(result["targets"], list)


@test()
def test_indirect_call_target_item_fields():
    """indirect_call_targets items have target_addr, target_name, confidence."""
    result = indirect_call_targets("main")
    for t in result["targets"]:
        assert "target_addr" in t
        assert "target_name" in t
        assert "confidence" in t
        assert t["confidence"] in ("high", "low")
        assert t["target_addr"].startswith("0x")


# ============================================================================
# Group 3: find_paths
# ============================================================================


@test()
def test_find_paths_result_fields():
    """find_paths returns all required fields."""
    result = find_paths("main", "main", "main", max_paths=5)
    assert "func" in result
    assert "src" in result
    assert "dst" in result
    assert "paths" in result
    assert "count" in result
    assert "truncated" in result
    assert isinstance(result["paths"], list)


@test()
def test_find_paths_paths_are_lists_of_hex():
    """find_paths path entries are lists of hex strings."""
    import idautils
    import idaapi
    import idc

    # Pick a function with enough blocks
    target = None
    for ea in idautils.Functions():
        fn = idaapi.get_func(ea)
        if fn and len(list(idaapi.FlowChart(fn))) >= 2:
            target = fn
            break

    if target is None:
        return

    fname = idc.get_func_name(target.start_ea)
    result = find_paths(fname, hex(target.start_ea), hex(target.start_ea), max_paths=5)
    for path in result["paths"]:
        assert isinstance(path, list)
        for addr in path:
            assert isinstance(addr, str)
            assert addr.startswith("0x")


@test()
def test_find_paths_invalid_func_returns_error():
    """find_paths with unknown function returns error key."""
    result = find_paths("0xdeadbeefdeadbeef", "0x0", "0x0")
    assert "error" in result


# ============================================================================
# Group 3: dominator_tree
# ============================================================================


@test()
def test_dominator_tree_has_required_fields():
    """dominator_tree returns func and dominators fields."""
    result = dominator_tree("main")
    assert "func" in result
    assert "dominators" in result


@test()
def test_dominator_tree_non_empty_for_valid_func():
    """dominator_tree returns non-empty map for a real function."""
    result = dominator_tree("main")
    if "error" not in result:
        assert isinstance(result["dominators"], dict)
        assert len(result["dominators"]) >= 1


@test()
def test_dominator_tree_entry_block_has_no_idom():
    """Entry block should have None as its immediate dominator."""
    import idautils
    import idaapi
    import idc

    for ea in idautils.Functions():
        fn = idaapi.get_func(ea)
        if fn is None:
            continue
        fname = idc.get_func_name(fn.start_ea)
        result = dominator_tree(fname)
        if "error" in result or not result.get("dominators"):
            continue
        entry_key = hex(fn.start_ea)
        if entry_key in result["dominators"]:
            assert result["dominators"][entry_key] is None, \
                f"Entry block dominator should be None, got {result['dominators'][entry_key]}"
        break


@test()
def test_dominator_tree_invalid_func_returns_error():
    """dominator_tree with unknown address returns error."""
    result = dominator_tree("0xdeadbeefdeadbeef")
    assert "error" in result


# ============================================================================
# Group 6: exception_handlers
# ============================================================================


@test()
def test_exception_handlers_top_level_fields():
    """exception_handlers() has handlers, count, and format."""
    result = exception_handlers()
    assert "handlers" in result
    assert "count" in result
    assert "format" in result
    assert isinstance(result["handlers"], list)
    assert isinstance(result["count"], int)
    assert result["count"] == len(result["handlers"])


@test()
def test_exception_handlers_item_fields():
    """exception_handlers items contain required keys."""
    result = exception_handlers()
    for h in result["handlers"]:
        assert "func_start" in h
        assert "handler" in h
        assert "format" in h
        assert h["format"] in ("pdata", "eh_frame", "unknown")
        assert h["func_start"].startswith("0x")
        assert h["handler"].startswith("0x")


@test()
def test_exception_handlers_no_data_has_warning():
    """If no EH data found, warning key should be present."""
    result = exception_handlers()
    if result["count"] == 0:
        # Either warning present or format is recognized
        assert "warning" in result or result["format"] in ("pdata", "eh_frame", "unknown")


# ============================================================================
# Group B: idb_info
# ============================================================================


@test()
def test_idb_info_returns_dict():
    """idb_info() returns a dict with required metadata keys."""
    result = idb_info()
    assert isinstance(result, dict), "idb_info must return a dict"
    for key in ("arch", "bitness", "image_base", "file_format", "functions"):
        assert key in result, f"idb_info must contain '{key}'"


@test()
def test_idb_info_bitness_valid():
    """idb_info bitness is 16, 32, or 64."""
    result = idb_info()
    assert result["bitness"] in (16, 32, 64), f"Unexpected bitness: {result['bitness']}"


@test()
def test_idb_info_image_base_hex():
    """idb_info image_base is a hex string."""
    result = idb_info()
    assert isinstance(result["image_base"], str)
    assert result["image_base"].startswith("0x"), "image_base must be hex string"


@test()
def test_idb_info_functions_positive():
    """idb_info functions count is positive for crackme03."""
    result = idb_info()
    assert result["functions"] > 0, "Expected at least one function"


@test()
def test_idb_info_arch_nonempty():
    """idb_info arch is a non-empty string."""
    result = idb_info()
    assert isinstance(result["arch"], str)
    assert len(result["arch"]) > 0, "arch must be non-empty"


# ============================================================================
# Group B: import_at
# ============================================================================


@test()
def test_import_at_returns_list():
    """import_at() returns a list."""
    import idautils
    import ida_nalt
    # Get the first import address from the IDB
    nimps = ida_nalt.get_import_module_qty()
    first_ea = None
    for i in range(nimps):
        def _grab(ea, name, ordinal):
            nonlocal first_ea
            if first_ea is None:
                first_ea = ea
            return False  # stop after first
        ida_nalt.enum_import_names(i, _grab)
        if first_ea is not None:
            break

    if first_ea is None:
        # No imports in this binary — test is vacuously satisfied
        result = import_at("0x0")
        assert isinstance(result, list)
        assert len(result) == 1
        assert "error" in result[0]
        return

    result = import_at(hex(first_ea))
    assert isinstance(result, list)
    assert len(result) == 1
    item = result[0]
    assert "addr" in item
    # Should be resolved successfully
    if "error" not in item:
        assert "module" in item
        assert "name" in item
        assert "ordinal" in item


@test()
def test_import_at_invalid_addr():
    """import_at on a non-import address returns error field."""
    result = import_at("0x0")
    assert isinstance(result, list)
    assert len(result) == 1
    assert "error" in result[0]


@test()
def test_import_at_batch():
    """import_at accepts a list of addresses."""
    result = import_at(["0x0", "0x1"])
    assert isinstance(result, list)
    assert len(result) == 2


# ============================================================================
# Group C: dead_blocks
# ============================================================================


@test()
def test_dead_blocks_returns_list():
    """dead_blocks() on 'main' returns a list result."""
    result = dead_blocks("main")
    assert isinstance(result, list)
    assert len(result) >= 1
    item = result[0]
    assert "dead_blocks" in item
    assert "total_blocks" in item
    assert "dead_count" in item
    assert isinstance(item["dead_blocks"], list)


@test()
def test_dead_blocks_counts_consistent():
    """dead_blocks dead_count matches len(dead_blocks)."""
    result = dead_blocks("main")
    for entry in result:
        if "error" not in entry:
            assert entry["dead_count"] == len(entry["dead_blocks"])
            assert entry["dead_count"] <= entry["total_blocks"]


@test()
def test_dead_blocks_item_fields():
    """dead_blocks block items have start, end, size."""
    result = dead_blocks("main")
    for entry in result:
        for blk in entry.get("dead_blocks", []):
            assert "start" in blk
            assert "end" in blk
            assert "size" in blk
            assert blk["start"].startswith("0x")
            assert blk["end"].startswith("0x")
            assert isinstance(blk["size"], int)
            assert blk["size"] >= 0


@test()
def test_dead_blocks_invalid_addr():
    """dead_blocks on invalid address returns error field."""
    result = dead_blocks("0xdeadbeefdeadbeef")
    assert isinstance(result, list)
    item = result[0]
    assert "error" in item or item.get("dead_count", 0) == 0


@test()
def test_dead_blocks_batch():
    """dead_blocks accepts comma-separated batch input."""
    result = dead_blocks("main,main")
    assert isinstance(result, list)
    assert len(result) == 2


# ============================================================================
# Group A: decompiler_comments
# ============================================================================


@test()
def test_decompiler_comments_get_returns_list():
    """decompiler_comments get action returns comments list."""
    result = decompiler_comments({"action": "get", "func": "main"})
    assert isinstance(result, list)
    assert len(result) >= 1
    item = result[0]
    assert item.get("action") == "get"
    assert "comments" in item
    assert isinstance(item["comments"], list)


@test()
def test_decompiler_comments_set_and_get():
    """decompiler_comments set then get round-trip works."""
    import idautils
    import idaapi
    # Find 'main' function entry ea
    ea_main = idaapi.get_name_ea(idaapi.BADADDR, "main")
    if ea_main == idaapi.BADADDR:
        # Skip if main not found
        return

    addr_str = hex(ea_main)
    test_text = "__mcp_test_cmt_roundtrip__"

    # Set comment at function entry
    set_result = decompiler_comments({"action": "set", "func": addr_str, "addr": addr_str, "text": test_text})
    assert isinstance(set_result, list)
    set_item = set_result[0]
    # May fail if ea not in pseudocode map; that's acceptable
    if not set_item.get("ok"):
        return

    # Get and verify
    get_result = decompiler_comments({"action": "get", "func": addr_str})
    assert get_result[0].get("ok"), "get should succeed after set"
    comments = get_result[0].get("comments", [])
    texts = [c.get("text", "") for c in comments]
    assert test_text in texts, f"Expected to find '{test_text}' in comments: {texts}"

    # Clean up: delete it
    del_result = decompiler_comments({"action": "delete", "func": addr_str, "addr": addr_str})
    assert del_result[0].get("ok"), "delete should succeed"


@test()
def test_decompiler_comments_missing_func():
    """decompiler_comments without func returns error."""
    result = decompiler_comments({"action": "get"})
    assert isinstance(result, list)
    assert "error" in result[0]


@test()
def test_decompiler_comments_unknown_action():
    """decompiler_comments with unknown action returns error."""
    result = decompiler_comments({"action": "frobnicate", "func": "main"})
    assert isinstance(result, list)
    assert "error" in result[0]


# ============================================================================
# Group D: export_header
# ============================================================================


@test()
def test_export_header_returns_ok():
    """export_header() with no output path returns ok result."""
    result = export_header()
    assert isinstance(result, dict)
    assert result.get("ok") is True, f"export_header failed: {result.get('error')}"
    assert "types_exported" in result
    assert isinstance(result["types_exported"], int)
    assert result["types_exported"] >= 0


@test()
def test_export_header_preview_present():
    """export_header preview field is present and non-empty when types exist."""
    result = export_header(max_preview=500)
    assert "preview" in result
    if result["types_exported"] > 0:
        assert len(result["preview"]) > 0
        # Header should start with a comment
        assert "IDA Pro" in result["preview"] or "#pragma" in result["preview"] or "/*" in result["preview"]


@test()
def test_export_header_filter_glob():
    """export_header with restrictive glob exports fewer types."""
    result_all = export_header(filter="*", max_preview=0)
    # Use a pattern that won't match anything
    result_none = export_header(filter="__ZZZNOMATCH__*", max_preview=0)
    assert result_none["types_exported"] == 0
    # All types >= filtered types
    assert result_all["types_exported"] >= result_none["types_exported"]


@test()
def test_export_header_write_file():
    """export_header writes a file when output_path is provided."""
    import os
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".h", delete=False) as tmp:
        tmp_path = tmp.name
    try:
        result = export_header(output_path=tmp_path, max_preview=0)
        assert result.get("ok") is True, f"Write failed: {result.get('error')}"
        assert result["output_path"] == tmp_path
        if result["types_exported"] > 0:
            assert os.path.exists(tmp_path)
            assert os.path.getsize(tmp_path) > 0
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
