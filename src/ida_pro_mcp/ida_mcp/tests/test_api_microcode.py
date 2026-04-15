"""Tests for api_microcode — microcode def-use chain analysis."""

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
from ..api_microcode import mcode_defuse, mcode_source, mcode_inspect

# crackme03.elf: main lives at 0x123e (same as other tests)
CRACKME_MAIN = "0x123e"

# Valid origin types returned by mcode_source
VALID_ORIGIN_TYPES = {"param", "global", "const", "retval", "unknown"}


# ============================================================================
# mcode_defuse
# ============================================================================


@test(binary="crackme03.elf")
def test_mcode_defuse_all_returns_list():
    """mcode_defuse on main with var='all' returns a non-empty list."""
    result = mcode_defuse(CRACKME_MAIN)
    assert_is_list(result, min_length=1)


@test(binary="crackme03.elf")
def test_mcode_defuse_entry_shape():
    """Each DefUseResult has the required keys with correct types."""
    result = mcode_defuse(CRACKME_MAIN)
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert_has_keys(entry, "var_name", "definitions", "uses")
    assert isinstance(entry["var_name"], str), "var_name must be a string"
    assert isinstance(entry["definitions"], list), "definitions must be a list"
    assert isinstance(entry["uses"], list), "uses must be a list"


@test(binary="crackme03.elf")
def test_mcode_defuse_site_shape():
    """Definition and use sites contain addr and text fields."""
    result = mcode_defuse(CRACKME_MAIN)
    # Find an entry that has at least one definition
    entry_with_def = next(
        (e for e in result if e["definitions"]), None
    )
    if entry_with_def is None:
        skip_test("No definition sites found in microcode")
    site = entry_with_def["definitions"][0]
    assert_has_keys(site, "addr", "text")
    assert isinstance(site["addr"], str)
    assert site["addr"].startswith("0x"), f"addr should be hex: {site['addr']!r}"


@test(binary="crackme03.elf")
def test_mcode_defuse_var_filter():
    """Filtering by a specific var name returns only that variable."""
    all_results = mcode_defuse(CRACKME_MAIN)
    if not all_results:
        skip_test("No variables found in microcode")
    target_var = all_results[0]["var_name"]
    filtered = mcode_defuse(CRACKME_MAIN, var=target_var)
    assert_is_list(filtered, min_length=1)
    assert len(filtered) == 1, (
        f"Expected exactly 1 result for var={target_var!r}, got {len(filtered)}"
    )
    assert filtered[0]["var_name"] == target_var


@test(binary="crackme03.elf")
def test_mcode_defuse_unknown_var_returns_empty():
    """Filtering by a non-existent variable name returns an empty list."""
    result = mcode_defuse(CRACKME_MAIN, var="__nonexistent_var_xyz__")
    assert_is_list(result)
    assert len(result) == 0, f"Expected empty list, got {len(result)} entries"


@test(binary="crackme03.elf")
def test_mcode_defuse_different_maturity():
    """mcode_defuse works at MMAT_LOCOPT maturity."""
    result = mcode_defuse(CRACKME_MAIN, maturity="MMAT_LOCOPT")
    assert_is_list(result)


@test(binary="crackme03.elf")
def test_mcode_defuse_invalid_addr():
    """mcode_defuse returns a list with an error entry for an invalid address."""
    result = mcode_defuse("0xdeadbeefdeadbeef")
    assert_is_list(result, min_length=1)
    assert "error" in result[0], f"Expected 'error' key in first element, got {result[0]}"


@test(binary="crackme03.elf")
def test_mcode_defuse_invalid_maturity():
    """mcode_defuse returns a list with an error entry for an unknown maturity string."""
    result = mcode_defuse(CRACKME_MAIN, maturity="MMAT_INVALID")
    assert_is_list(result, min_length=1)
    assert "error" in result[0], f"Expected 'error' key in first element, got {result[0]}"


# ============================================================================
# mcode_source
# ============================================================================


@test(binary="crackme03.elf")
def test_mcode_source_valid_origin_type():
    """mcode_source returns a valid origin_type for the first variable."""
    all_vars = mcode_defuse(CRACKME_MAIN)
    if not all_vars:
        skip_test("No variables found in microcode")
    # Pick a variable that has at least one definition
    target = next((e for e in all_vars if e["definitions"]), None)
    if target is None:
        skip_test("No variables with definitions found")
    result = mcode_source(CRACKME_MAIN, var=target["var_name"])
    assert_has_keys(result, "var", "origin_type", "origin_detail", "chain")
    assert result["origin_type"] in VALID_ORIGIN_TYPES, (
        f"origin_type {result['origin_type']!r} not in {VALID_ORIGIN_TYPES}"
    )


@test(binary="crackme03.elf")
def test_mcode_source_chain_structure():
    """Each chain step has addr, text, and step fields."""
    all_vars = mcode_defuse(CRACKME_MAIN)
    target = next((e for e in all_vars if e["definitions"]), None)
    if target is None:
        skip_test("No variables with definitions found")
    result = mcode_source(CRACKME_MAIN, var=target["var_name"])
    chain = result.get("chain", [])
    assert isinstance(chain, list)
    for step in chain:
        assert_has_keys(step, "addr", "text", "step")
        assert isinstance(step["step"], int)


@test(binary="crackme03.elf")
def test_mcode_source_unknown_var_returns_error():
    """mcode_source returns error when var is not found."""
    result = mcode_source(CRACKME_MAIN, var="__nonexistent_xyz__")
    assert "error" in result, "Expected 'error' key for unknown variable"


@test(binary="crackme03.elf")
def test_mcode_source_max_depth_clamped():
    """mcode_source clamps max_depth to 20."""
    all_vars = mcode_defuse(CRACKME_MAIN)
    target = next((e for e in all_vars if e["definitions"]), None)
    if target is None:
        skip_test("No variables with definitions found")
    # Should not crash with excessive depth
    result = mcode_source(CRACKME_MAIN, var=target["var_name"], max_depth=9999)
    assert_has_keys(result, "var", "origin_type", "chain")
    assert len(result["chain"]) <= 20, "Chain length should not exceed max_depth=20"


@test(binary="crackme03.elf")
def test_mcode_source_invalid_addr():
    """mcode_source returns an error dict for an invalid address."""
    result = mcode_source("0xdeadbeefdeadbeef", var="x")
    assert "error" in result, f"Expected 'error' key in result, got {result}"


# ============================================================================
# mcode_inspect
# ============================================================================


@test(binary="crackme03.elf")
def test_mcode_inspect_basic_shape():
    """mcode_inspect returns correct top-level structure."""
    result = mcode_inspect(CRACKME_MAIN)
    assert_has_keys(result, "maturity", "block_count", "insn_count", "blocks")
    assert result["maturity"] == "MMAT_GLBOPT1"
    assert isinstance(result["block_count"], int) and result["block_count"] > 0
    assert isinstance(result["insn_count"], int) and result["insn_count"] > 0
    assert_is_list(result["blocks"], min_length=1)


@test(binary="crackme03.elf")
def test_mcode_inspect_block_shape():
    """Each block has required fields with correct types."""
    result = mcode_inspect(CRACKME_MAIN)
    block = result["blocks"][0]
    assert_has_keys(block, "index", "start_addr", "instructions", "succs", "preds")
    assert isinstance(block["index"], int)
    assert isinstance(block["start_addr"], str)
    assert isinstance(block["instructions"], list)
    assert isinstance(block["succs"], list)
    assert isinstance(block["preds"], list)


@test(binary="crackme03.elf")
def test_mcode_inspect_insn_shape():
    """Each instruction entry has addr, opcode, and text."""
    result = mcode_inspect(CRACKME_MAIN)
    insns = [i for b in result["blocks"] for i in b["instructions"]]
    assert len(insns) > 0, "Expected at least one instruction"
    insn = insns[0]
    assert_has_keys(insn, "addr", "opcode", "text")
    assert isinstance(insn["addr"], str)
    assert insn["addr"].startswith("0x"), f"addr should be hex: {insn['addr']!r}"
    assert isinstance(insn["opcode"], int)
    assert isinstance(insn["text"], str)


@test(binary="crackme03.elf")
def test_mcode_inspect_different_maturity():
    """mcode_inspect works at MMAT_LOCOPT and returns valid blocks."""
    result = mcode_inspect(CRACKME_MAIN, maturity="MMAT_LOCOPT")
    assert_has_keys(result, "maturity", "block_count", "blocks")
    assert result["maturity"] == "MMAT_LOCOPT"
    assert result["block_count"] > 0


@test(binary="crackme03.elf")
def test_mcode_inspect_block_filter_single():
    """block_filter='0' restricts output to only block 0."""
    result = mcode_inspect(CRACKME_MAIN, block_filter="0")
    assert_has_keys(result, "blocks")
    for block in result["blocks"]:
        assert block["index"] == 0, (
            f"Expected only block 0, got block {block['index']}"
        )


@test(binary="crackme03.elf")
def test_mcode_inspect_block_filter_range():
    """block_filter='0-2' restricts output to blocks 0, 1, 2."""
    result = mcode_inspect(CRACKME_MAIN, block_filter="0-2")
    for block in result["blocks"]:
        assert 0 <= block["index"] <= 2, (
            f"Block index {block['index']} out of expected range 0-2"
        )


@test(binary="crackme03.elf")
def test_mcode_inspect_pagination():
    """Pagination via offset/count returns a subset of instructions."""
    full = mcode_inspect(CRACKME_MAIN, count=500)
    total = full["insn_count"]
    if total < 2:
        skip_test("Not enough instructions to test pagination")
    half = total // 2
    paged = mcode_inspect(CRACKME_MAIN, offset=half, count=500)
    paged_insns = [i for b in paged["blocks"] for i in b["instructions"]]
    full_insns = [i for b in full["blocks"] for i in b["instructions"]]
    # Paged result should have fewer or equal instructions than full
    assert len(paged_insns) <= len(full_insns), (
        "Paged result should not exceed full result"
    )
    # And paged should start after the offset
    assert len(paged_insns) <= total - half + 1


@test(binary="crackme03.elf")
def test_mcode_inspect_count_clamped():
    """count is clamped to 500 maximum."""
    result = mcode_inspect(CRACKME_MAIN, count=9999)
    insns = [i for b in result["blocks"] for i in b["instructions"]]
    assert len(insns) <= 500, f"Expected at most 500 instructions, got {len(insns)}"


@test(binary="crackme03.elf")
def test_mcode_inspect_invalid_addr():
    """mcode_inspect raises an error for an invalid address."""
    result = mcode_inspect("0xdeadbeefdeadbeef")
    assert_error(result)


@test(binary="crackme03.elf")
def test_mcode_inspect_invalid_maturity():
    """mcode_inspect raises an error for an unknown maturity string."""
    result = mcode_inspect(CRACKME_MAIN, maturity="MMAT_BOGUS")
    assert_error(result)
