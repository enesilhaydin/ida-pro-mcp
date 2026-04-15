"""Tests for api_vuln — vuln scan orchestration, crypto detection, attack surface, mitigations."""

from ..framework import (
    test,
    skip_test,
    assert_is_list,
    assert_ok,
    assert_has_keys,
    get_any_function,
)
from ..api_vuln import (
    vuln_scan,
    vuln_deep,
    vuln_patterns,
    vuln_pattern_add,
    crypto_scan,
    attack_surface,
    check_mitigations,
)

CRACKME_MAIN = "0x123e"


# ============================================================================
# vuln_scan
# ============================================================================


@test(binary="crackme03.elf")
def test_vuln_scan_all_returns_structure():
    """vuln_scan('all') returns the expected top-level structure."""
    result = vuln_scan(scope="all", count=50, max_functions=50)
    assert_has_keys(result, "scanned_functions", "total_findings", "findings", "summary")
    assert isinstance(result["scanned_functions"], int)
    assert result["scanned_functions"] >= 0
    assert isinstance(result["total_findings"], int)
    assert isinstance(result["findings"], list)
    summary = result["summary"]
    assert isinstance(summary, dict)
    assert "by_category" in summary
    assert "by_severity" in summary


@test(binary="crackme03.elf")
def test_vuln_scan_all_findings_structure():
    """Each finding in vuln_scan has the required fields with valid values."""
    result = vuln_scan(scope="all", count=100, max_functions=100)
    for finding in result["findings"]:
        assert_has_keys(finding, "id", "addr", "func_name", "pattern_name", "category", "severity", "snippet")
        assert finding["severity"] in ("low", "medium", "high", "critical"), (
            f"Unexpected severity: {finding['severity']!r}"
        )
        assert finding["addr"].startswith("0x"), f"addr should be hex: {finding['addr']!r}"
        assert finding["id"].startswith("vuln_")


@test(binary="crackme03.elf")
def test_vuln_scan_single_function():
    """vuln_scan on a single function returns a result scoped to that function."""
    result = vuln_scan(scope=CRACKME_MAIN)
    assert_has_keys(result, "scanned_functions", "total_findings", "findings", "summary")
    assert result["scanned_functions"] <= 1
    # All findings should belong to the scanned function; check func_name is set
    for finding in result["findings"]:
        assert finding["func_name"] is not None, (
            f"Finding is missing func_name: {finding!r}"
        )


@test(binary="crackme03.elf")
def test_vuln_scan_category_filter():
    """vuln_scan with category=memory only returns memory findings."""
    result = vuln_scan(scope="all", categories="memory", count=100, max_functions=100)
    for finding in result["findings"]:
        assert finding["category"] == "memory", (
            f"Expected category 'memory', got {finding['category']!r}"
        )


@test(binary="crackme03.elf")
def test_vuln_scan_severity_filter():
    """vuln_scan with severity_min=high only returns high/critical findings."""
    result = vuln_scan(scope="all", severity_min="high", count=100, max_functions=100)
    for finding in result["findings"]:
        assert finding["severity"] in ("high", "critical"), (
            f"Expected high/critical severity, got {finding['severity']!r}"
        )


@test(binary="crackme03.elf")
def test_vuln_scan_pagination():
    """vuln_scan pagination returns distinct slices."""
    all_result = vuln_scan(scope="all", offset=0, count=1000, max_functions=100)
    if all_result["total_findings"] < 2:
        skip_test("fewer than 2 findings — cannot test pagination")
    page0 = vuln_scan(scope="all", offset=0, count=1, max_functions=100)
    page1 = vuln_scan(scope="all", offset=1, count=1, max_functions=100)
    assert len(page0["findings"]) == 1
    assert len(page1["findings"]) == 1
    assert page0["findings"][0]["id"] != page1["findings"][0]["id"]


# ============================================================================
# vuln_deep
# ============================================================================


@test(binary="crackme03.elf")
def test_vuln_deep_returns_structure():
    """vuln_deep returns the required top-level structure."""
    result = vuln_deep(addr=CRACKME_MAIN)
    assert_has_keys(result, "exploitability", "recommendation")
    assert result["exploitability"] in ("low", "medium", "high", "critical", "unknown")
    assert isinstance(result["recommendation"], str)
    assert len(result["recommendation"]) > 0


@test(binary="crackme03.elf")
def test_vuln_deep_finding_field():
    """vuln_deep includes a finding dict with addr and func_name."""
    result = vuln_deep(addr=CRACKME_MAIN)
    if "error" in result:
        skip_test(f"vuln_deep returned error: {result['error']}")
    assert "finding" in result
    finding = result["finding"]
    assert_has_keys(finding, "addr", "func_name", "matches")
    assert isinstance(finding["matches"], list)


@test(binary="crackme03.elf")
def test_vuln_deep_with_specific_pattern():
    """vuln_deep with a specific pattern focuses analysis."""
    result = vuln_deep(addr=CRACKME_MAIN, pattern="printf_format_arg")
    assert_has_keys(result, "exploitability", "recommendation")
    if "finding" in result:
        for match in result["finding"].get("matches", []):
            assert match["pattern_name"] == "printf_format_arg"


@test(binary="crackme03.elf")
def test_vuln_deep_invalid_addr():
    """vuln_deep on an invalid address returns an error result."""
    result = vuln_deep(addr="0x0")
    assert "error" in result or result["exploitability"] == "unknown"


# ============================================================================
# vuln_patterns
# ============================================================================


@test()
def test_vuln_patterns_list_all():
    """vuln_patterns() returns at least 20 patterns."""
    result = vuln_patterns()
    assert_is_list(result, min_length=20)
    for p in result:
        assert_has_keys(p, "name", "category", "severity", "targets", "check",
                        "arg_index", "description", "is_builtin")
        assert p["severity"] in ("low", "medium", "high", "critical"), (
            f"Invalid severity {p['severity']!r} in pattern {p['name']!r}"
        )


@test()
def test_vuln_patterns_category_filter():
    """vuln_patterns with category=memory only returns memory patterns."""
    result = vuln_patterns(category="memory")
    assert_is_list(result, min_length=1)
    for p in result:
        assert p["category"] == "memory", (
            f"Expected 'memory', got {p['category']!r}"
        )


@test()
def test_vuln_patterns_include_builtin_false():
    """vuln_patterns(include_builtin=False) returns only runtime patterns."""
    result = vuln_patterns(include_builtin=False)
    assert isinstance(result, list)
    for p in result:
        assert not p["is_builtin"], "Expected only runtime (non-builtin) patterns"


@test()
def test_vuln_patterns_known_builtins_present():
    """Known builtin patterns are all present in the registry."""
    result = vuln_patterns()
    names = {p["name"] for p in result}
    for expected in (
        "printf_format_arg",
        "unchecked_memcpy_size",
        "malloc_null_unchecked",
        "use_after_free",
        "system_user_input",
        "weak_random",
        "double_free",
        "stack_buffer_gets",
    ):
        assert expected in names, f"Missing expected builtin pattern: {expected!r}"


# ============================================================================
# vuln_pattern_add
# ============================================================================


@test()
def test_vuln_pattern_add_and_verify():
    """vuln_pattern_add registers a new pattern that appears in vuln_patterns."""
    res = vuln_pattern_add(
        name="test_custom_alloc_check",
        category="missing_check",
        severity="high",
        targets="my_alloc,my_calloc",
        check="return_unchecked",
        arg_index=-1,
        description="Custom allocator return not checked",
    )
    assert_has_keys(res, "ok", "pattern")
    assert res["ok"] is True, f"vuln_pattern_add failed: {res}"
    assert_has_keys(res["pattern"], "name", "category", "severity", "targets",
                    "check", "arg_index", "description", "is_builtin")
    assert res["pattern"]["name"] == "test_custom_alloc_check"
    assert res["pattern"]["is_builtin"] is False

    # Verify it now appears in vuln_patterns
    all_patterns = vuln_patterns()
    names = {p["name"] for p in all_patterns}
    assert "test_custom_alloc_check" in names, (
        "Newly added pattern not found in vuln_patterns() output"
    )


@test()
def test_vuln_pattern_add_invalid_severity():
    """vuln_pattern_add rejects invalid severity."""
    res = vuln_pattern_add(
        name="test_bad_sev",
        category="memory",
        severity="extreme",
        targets="memcpy",
        check="arg_size_unbounded",
    )
    assert res.get("ok") is False
    assert "error" in res


@test()
def test_vuln_pattern_add_invalid_check():
    """vuln_pattern_add rejects unknown check type."""
    res = vuln_pattern_add(
        name="test_bad_check",
        category="memory",
        severity="high",
        targets="memcpy",
        check="__nonexistent_check__",
    )
    assert res.get("ok") is False
    assert "error" in res


# ============================================================================
# crypto_scan
# ============================================================================


@test(binary="crackme03.elf")
def test_crypto_scan_returns_list():
    """crypto_scan returns a list (possibly empty)."""
    result = crypto_scan()
    assert isinstance(result, list), f"Expected list, got {type(result)}"


@test(binary="crackme03.elf")
def test_crypto_scan_hit_structure():
    """Each crypto_scan hit has the required fields."""
    result = crypto_scan()
    for hit in result:
        if "error" in hit:
            continue
        assert_has_keys(hit, "algorithm", "constant_name", "addr", "match_type")
        assert hit["addr"].startswith("0x"), f"addr should be hex: {hit['addr']!r}"
        assert hit["match_type"] in ("immediate", "byte_sequence"), (
            f"Unexpected match_type: {hit['match_type']!r}"
        )


@test(binary="crackme03.elf")
def test_crypto_scan_algorithm_filter():
    """crypto_scan with a specific algorithm only returns hits for that algorithm."""
    result = crypto_scan(algorithms="sha256")
    for hit in result:
        if "error" in hit:
            continue
        assert hit["algorithm"] == "sha256", (
            f"Expected 'sha256', got {hit['algorithm']!r}"
        )


@test(binary="crackme03.elf")
def test_crypto_scan_multiple_algorithms():
    """crypto_scan with multiple algorithms returns hits for each."""
    result = crypto_scan(algorithms="sha256,md5,tea")
    for hit in result:
        if "error" in hit:
            continue
        assert hit["algorithm"] in ("sha256", "md5", "tea"), (
            f"Unexpected algorithm: {hit['algorithm']!r}"
        )


# ============================================================================
# attack_surface
# ============================================================================


@test(binary="crackme03.elf")
def test_attack_surface_returns_structure():
    """attack_surface returns the required top-level structure."""
    result = attack_surface()
    assert_has_keys(result, "present_input_functions", "present_sink_functions",
                    "attack_paths", "total_paths")
    assert isinstance(result["present_input_functions"], dict)
    assert isinstance(result["present_sink_functions"], dict)
    assert isinstance(result["attack_paths"], list)
    assert isinstance(result["total_paths"], int)
    assert result["total_paths"] >= 0


@test(binary="crackme03.elf")
def test_attack_surface_input_categories():
    """attack_surface present_input_functions has expected category keys."""
    result = attack_surface()
    for cat in ("network", "file", "stdin", "argv", "env"):
        assert cat in result["present_input_functions"], (
            f"Missing input category: {cat!r}"
        )


@test(binary="crackme03.elf")
def test_attack_surface_sink_categories():
    """attack_surface present_sink_functions has expected category keys."""
    result = attack_surface()
    for cat in ("memory", "format", "command", "file"):
        assert cat in result["present_sink_functions"], (
            f"Missing sink category: {cat!r}"
        )


@test(binary="crackme03.elf")
def test_attack_surface_path_structure():
    """Each attack path entry has required fields."""
    result = attack_surface()
    for path in result["attack_paths"]:
        assert_has_keys(path, "bridge_addr", "bridge_name", "input_func", "sink_func", "risk")
        assert path["bridge_addr"].startswith("0x")
        assert isinstance(path["input_func"], str)
        assert isinstance(path["sink_func"], str)


@test(binary="crackme03.elf")
def test_attack_surface_sink_filter():
    """attack_surface with sink_categories=memory only returns memory sinks."""
    result = attack_surface(sink_categories="memory")
    assert "memory" in result["present_sink_functions"]
    # Other categories should be absent from sink dict
    for cat in ("format", "command", "file"):
        assert cat not in result["present_sink_functions"], (
            f"Category {cat!r} should not be present when filtering for memory only"
        )


# ============================================================================
# check_mitigations
# ============================================================================


@test(binary="crackme03.elf")
def test_check_mitigations_structure():
    """check_mitigations returns the required top-level structure."""
    result = check_mitigations()
    assert_has_keys(result, "file_type", "mitigations", "risk_notes")
    mitigations = result["mitigations"]
    assert_has_keys(mitigations, "nx", "pie", "stack_canary", "rwx_segments", "fortify")


@test(binary="crackme03.elf")
def test_check_mitigations_types():
    """check_mitigations returns correctly typed fields."""
    result = check_mitigations()
    m = result["mitigations"]
    assert isinstance(m["nx"], bool), f"nx should be bool, got {type(m['nx'])}"
    assert isinstance(m["pie"], bool), f"pie should be bool, got {type(m['pie'])}"
    assert isinstance(m["stack_canary"], bool), (
        f"stack_canary should be bool, got {type(m['stack_canary'])}"
    )
    assert isinstance(m["rwx_segments"], list), (
        f"rwx_segments should be list, got {type(m['rwx_segments'])}"
    )
    assert isinstance(m["fortify"], bool), f"fortify should be bool, got {type(m['fortify'])}"
    assert isinstance(result["risk_notes"], list)


@test(binary="crackme03.elf")
def test_check_mitigations_rwx_segment_structure():
    """Each RWX segment entry has required fields."""
    result = check_mitigations()
    for seg in result["mitigations"]["rwx_segments"]:
        assert_has_keys(seg, "name", "start", "end", "perm")
        assert seg["start"].startswith("0x")
        assert seg["end"].startswith("0x")


@test(binary="crackme03.elf")
def test_check_mitigations_file_type_string():
    """check_mitigations file_type is a non-empty string."""
    result = check_mitigations()
    assert isinstance(result["file_type"], str)
    assert len(result["file_type"]) > 0


@test()
def test_check_mitigations_generic():
    """check_mitigations works on any binary."""
    result = check_mitigations()
    assert_has_keys(result, "file_type", "mitigations", "risk_notes")
    m = result["mitigations"]
    for key in ("nx", "pie", "stack_canary", "rwx_segments", "fortify"):
        assert key in m, f"Missing mitigation key: {key!r}"
