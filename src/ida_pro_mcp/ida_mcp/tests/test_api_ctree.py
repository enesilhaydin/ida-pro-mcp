"""Tests for api_ctree — ctree traversal engine + vulnerability pattern matching."""

from ..framework import (
    test,
    skip_test,
    assert_is_list,
    assert_ok,
    assert_error,
    assert_has_keys,
    get_any_function,
    get_named_function,
)
from ..api_ctree import (
    ctree_query,
    ctree_match,
    ctree_callers_of,
    ctree_vars,
    get_pattern_registry,
)

# crackme03.elf: main lives at 0x123e (same as test_api_stack.py)
CRACKME_MAIN = "0x123e"


# ============================================================================
# ctree_query
# ============================================================================


@test(binary="crackme03.elf")
def test_ctree_query_returns_nodes():
    """ctree_query on main returns a non-empty list of nodes."""
    result = ctree_query(CRACKME_MAIN)
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert_has_keys(entry, "addr", "node_type", "text")
    assert isinstance(entry["addr"], str)
    assert isinstance(entry["node_type"], str)
    assert isinstance(entry["text"], str)


@test(binary="crackme03.elf")
def test_ctree_query_filter_by_call():
    """Filtering by node_type=call returns only call nodes."""
    result = ctree_query(CRACKME_MAIN, node_types="call")
    assert_is_list(result)
    for node in result:
        assert node["node_type"] == "call", (
            f"Expected 'call', got {node['node_type']!r}"
        )


@test(binary="crackme03.elf")
def test_ctree_query_filter_by_compare():
    """Filtering by node_type=compare returns only compare nodes."""
    result = ctree_query(CRACKME_MAIN, node_types="compare")
    assert_is_list(result)
    for node in result:
        assert node["node_type"] == "compare", (
            f"Expected 'compare', got {node['node_type']!r}"
        )


@test(binary="crackme03.elf")
def test_ctree_query_text_filter():
    """Text filter narrows results to nodes whose text contains the substring."""
    # First get all nodes to find a term that should exist
    all_nodes = ctree_query(CRACKME_MAIN)
    assert_is_list(all_nodes, min_length=1)
    # Pick the text of the first node and use it as filter
    first_text = all_nodes[0]["text"]
    if not first_text:
        skip_test("first node has empty text")
    # Use first 4 chars as filter to avoid overly restrictive match
    prefix = first_text[:4]
    filtered = ctree_query(CRACKME_MAIN, filter=prefix)
    assert_is_list(filtered)
    for node in filtered:
        assert prefix.lower() in node["text"].lower(), (
            f"Text {node['text']!r} does not contain filter {prefix!r}"
        )


@test(binary="crackme03.elf")
def test_ctree_query_pagination():
    """Pagination returns the correct slice of results."""
    all_nodes = ctree_query(CRACKME_MAIN, offset=0, count=1000)
    if len(all_nodes) < 2:
        skip_test("not enough nodes to test pagination")
    page0 = ctree_query(CRACKME_MAIN, offset=0, count=1)
    page1 = ctree_query(CRACKME_MAIN, offset=1, count=1)
    assert len(page0) == 1
    assert len(page1) == 1
    assert page0[0]["text"] != page1[0]["text"] or page0[0]["addr"] != page1[0]["addr"]


@test(binary="crackme03.elf")
def test_ctree_query_invalid_addr_returns_error():
    """ctree_query on a non-function address returns a result with error field."""
    result = ctree_query("0x0")
    assert_is_list(result, min_length=1)
    assert_error(result[0])


@test()
def test_ctree_query_generic_any_function():
    """ctree_query works on any function in any binary."""
    addr = get_any_function()
    if not addr:
        skip_test("no functions in binary")
    result = ctree_query(addr)
    # May fail decompilation — just ensure we get a list back
    assert isinstance(result, list)


# ============================================================================
# ctree_match
# ============================================================================


@test(binary="crackme03.elf")
def test_ctree_match_specific_pattern_returns_list():
    """ctree_match with a specific pattern returns a list (possibly empty)."""
    result = ctree_match(addr=CRACKME_MAIN, pattern="printf_format_arg")
    assert_is_list(result)
    for match in result:
        assert_has_keys(match, "addr", "func_name", "pattern_name", "category", "severity", "snippet")
        assert match["pattern_name"] == "printf_format_arg"


@test(binary="crackme03.elf")
def test_ctree_match_all_patterns_on_main():
    """ctree_match with all patterns on main returns structured results."""
    result = ctree_match(addr=CRACKME_MAIN, pattern="all")
    assert_is_list(result)
    for match in result:
        assert_has_keys(match, "addr", "func_name", "pattern_name", "category", "severity", "snippet")
        assert match["severity"] in ("low", "medium", "high", "critical")
        assert match["category"] in (
            "memory", "format_string", "integer", "uaf",
            "missing_check", "command_injection", "crypto", "custom", "error"
        )


@test(binary="crackme03.elf")
def test_ctree_match_binary_wide():
    """ctree_match addr='all' iterates the binary and returns a list."""
    result = ctree_match(addr="all", pattern="printf_format_arg", count=50)
    assert_is_list(result)
    # All results should carry the expected structure
    for match in result:
        assert_has_keys(match, "addr", "func_name", "pattern_name", "category", "severity", "snippet")


@test(binary="crackme03.elf")
def test_ctree_match_category_filter():
    """ctree_match category filter restricts results to that category."""
    result = ctree_match(addr="all", categories="memory", count=50)
    assert_is_list(result)
    for match in result:
        assert match["category"] == "memory", (
            f"Expected 'memory' category, got {match['category']!r}"
        )


@test(binary="crackme03.elf")
def test_ctree_match_unknown_pattern_returns_empty():
    """ctree_match with an unknown pattern name returns empty list."""
    result = ctree_match(addr=CRACKME_MAIN, pattern="__nonexistent_pattern__")
    assert_is_list(result)
    assert len(result) == 0


@test()
def test_ctree_match_pattern_registry_has_builtins():
    """get_pattern_registry() returns all ~25 builtin patterns."""
    registry = get_pattern_registry()
    assert isinstance(registry, dict)
    assert len(registry) >= 20, f"Expected at least 20 builtins, got {len(registry)}"
    # Spot-check a few required patterns
    for name in ("printf_format_arg", "unchecked_memcpy_size", "malloc_null_unchecked",
                  "use_after_free", "system_user_input", "weak_random"):
        assert name in registry, f"Missing builtin pattern: {name}"
    # Each entry should have required keys
    for name, p in registry.items():
        for key in ("name", "category", "severity", "targets", "check", "arg_index",
                    "description", "is_builtin"):
            assert key in p, f"Pattern {name!r} missing key {key!r}"
        assert p["severity"] in ("low", "medium", "high", "critical"), (
            f"Pattern {name!r} has invalid severity {p['severity']!r}"
        )


# ============================================================================
# ctree_callers_of
# ============================================================================


@test(binary="crackme03.elf")
def test_ctree_callers_of_printf():
    """ctree_callers_of('printf') returns call sites with args."""
    result = ctree_callers_of("printf", include_args=True, include_condition=True)
    assert_is_list(result)
    for entry in result:
        assert_has_keys(entry, "caller_addr", "caller_name", "call_addr", "args")
        assert isinstance(entry["args"], list)
        assert entry["caller_addr"].startswith("0x")
        assert entry["call_addr"].startswith("0x")


@test(binary="crackme03.elf")
def test_ctree_callers_of_args_content():
    """ctree_callers_of returns non-empty arg text for printf calls."""
    result = ctree_callers_of("printf", include_args=True)
    assert_is_list(result)
    if not result:
        skip_test("no printf callers found in crackme03.elf")
    # At least one entry should have args
    any_has_args = any(len(e["args"]) > 0 for e in result)
    assert any_has_args, "Expected at least one call site with args"


@test(binary="crackme03.elf")
def test_ctree_callers_of_no_args():
    """ctree_callers_of with include_args=False returns empty arg lists."""
    result = ctree_callers_of("printf", include_args=False)
    assert_is_list(result)
    for entry in result:
        assert entry["args"] == [], (
            f"Expected empty args list when include_args=False, got {entry['args']}"
        )


@test(binary="crackme03.elf")
def test_ctree_callers_of_pagination():
    """ctree_callers_of pagination returns correct slice."""
    all_results = ctree_callers_of("printf", offset=0, count=200)
    if len(all_results) < 2:
        skip_test("fewer than 2 printf call sites")
    page0 = ctree_callers_of("printf", offset=0, count=1)
    page1 = ctree_callers_of("printf", offset=1, count=1)
    assert len(page0) == 1
    assert len(page1) == 1


@test()
def test_ctree_callers_of_nonexistent_target():
    """ctree_callers_of a non-existent function returns empty list or error entry."""
    result = ctree_callers_of("__nonexistent_func_xyz__")
    assert isinstance(result, list)


# ============================================================================
# ctree_vars
# ============================================================================


@test(binary="crackme03.elf")
def test_ctree_vars_main_returns_variables():
    """ctree_vars on main returns a non-empty list of variable info."""
    result = ctree_vars(CRACKME_MAIN)
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert_has_keys(entry, "name", "type", "is_param", "is_stack", "size", "source")
    assert isinstance(entry["is_param"], bool)
    assert isinstance(entry["is_stack"], bool)
    assert isinstance(entry["size"], int)
    assert entry["source"] in ("param", "stack", "register")


@test(binary="crackme03.elf")
def test_ctree_vars_params_present():
    """ctree_vars identifies at least some parameter variables."""
    result = ctree_vars(CRACKME_MAIN)
    assert_is_list(result, min_length=1)
    params = [v for v in result if v["is_param"]]
    # main has argc and argv
    assert len(params) >= 1, "Expected at least one parameter variable in main"


@test(binary="crackme03.elf")
def test_ctree_vars_filter():
    """ctree_vars filter narrows results by name/type substring."""
    result = ctree_vars(CRACKME_MAIN)
    assert_is_list(result, min_length=1)
    if not result:
        skip_test("no vars returned")
    # Use a fragment of the first var's name as filter
    first_name = result[0]["name"]
    if not first_name or first_name.startswith("<"):
        skip_test("first var has synthetic name")
    frag = first_name[:3]
    filtered = ctree_vars(CRACKME_MAIN, filter=frag)
    assert_is_list(filtered)
    for v in filtered:
        assert frag.lower() in v["name"].lower() or frag.lower() in v["type"].lower(), (
            f"Filter {frag!r} not found in name={v['name']!r} or type={v['type']!r}"
        )


@test(binary="crackme03.elf")
def test_ctree_vars_invalid_addr_returns_error():
    """ctree_vars on a non-function address returns an error entry."""
    result = ctree_vars("0x0")
    assert_is_list(result, min_length=1)
    # The error entry has type set to the error message
    assert result[0]["name"] == "error"
    assert result[0]["type"]  # non-empty error message


@test()
def test_ctree_vars_generic_any_function():
    """ctree_vars on any function returns a list."""
    addr = get_any_function()
    if not addr:
        skip_test("no functions in binary")
    result = ctree_vars(addr)
    assert isinstance(result, list)
