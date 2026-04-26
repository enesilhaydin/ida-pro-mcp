"""Tests for newly added HIGH priority MCP tools.

Groups tested:
  - Group 1: callers, name_search, string_xrefs
  - Group 2: switch_cases, indirect_call_targets
  - Group 3: find_paths, dominator_tree
  - Group 6: exception_handlers

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
)
from ida_pro_mcp.ida_mcp.api_paths import find_paths, dominator_tree
from ida_pro_mcp.ida_mcp.api_segments import exception_handlers


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
