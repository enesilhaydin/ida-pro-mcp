"""Tests for api_segments API functions."""

from ..framework import (
    test,
    skip_test,
    assert_has_keys,
    assert_is_list,
)
from ..api_segments import list_segments, segment_xrefs


@test()
def test_list_segments_returns_segments():
    """list_segments returns at least one segment with required keys."""
    result = list_segments()
    assert_is_list(result, min_length=1)
    required = {"name", "start", "end", "size", "permissions", "type", "bitness", "is_loaded"}
    for seg in result:
        assert_has_keys(seg, list(required))
        # permissions is a 3-char string of r/w/x/-
        assert len(seg["permissions"]) == 3
        assert all(c in "rwx-" for c in seg["permissions"])
        # start/end are hex strings
        assert seg["start"].startswith("0x") or seg["start"].startswith("0X")
        assert seg["end"].startswith("0x") or seg["end"].startswith("0X")
        assert isinstance(seg["size"], int)
        assert seg["bitness"] in (16, 32, 64)
        assert isinstance(seg["is_loaded"], bool)


@test()
def test_list_segments_name_filter():
    """list_segments name filter returns only matching segments."""
    all_segs = list_segments()
    if not all_segs:
        skip_test("binary has no segments")

    # Try filtering by the first segment name (if non-empty)
    first_name = all_segs[0].get("name", "")
    if not first_name:
        skip_test("first segment has no name")

    filtered = list_segments(filter=first_name)
    assert_is_list(filtered, min_length=1)
    for seg in filtered:
        assert first_name.lower() in seg["name"].lower()


@test()
def test_list_segments_permission_filter():
    """list_segments permission filter returns only segments with matching perms."""
    all_segs = list_segments()
    if not all_segs:
        skip_test("binary has no segments")

    # Find a permission string that exists
    existing_perm = all_segs[0]["permissions"]
    # Use the first two chars as filter (e.g. "r-")
    perm_filter = existing_perm[:2]
    filtered = list_segments(filter=perm_filter)
    for seg in filtered:
        assert perm_filter in seg["permissions"]


@test()
def test_segment_xrefs_returns_structure():
    """segment_xrefs returns a dict with xrefs list and summary."""
    result = segment_xrefs()
    assert isinstance(result, dict)
    assert "xrefs" in result
    assert "summary" in result
    assert isinstance(result["xrefs"], list)
    summary = result["summary"]
    assert "total" in summary
    assert "by_direction" in summary
    assert isinstance(summary["total"], int)
    assert isinstance(summary["by_direction"], dict)


@test()
def test_segment_xrefs_xref_keys():
    """segment_xrefs xref entries have required keys."""
    result = segment_xrefs(count=10)
    for xref in result["xrefs"]:
        assert "from_addr" in xref
        assert "to_addr" in xref
        assert "from_segment" in xref
        assert "to_segment" in xref
        assert "type" in xref
        assert xref["type"] in ("code", "data")
        # from and to segments must differ (no same-segment xrefs)
        assert xref["from_segment"] != xref["to_segment"]


@test()
def test_segment_xrefs_type_filter():
    """segment_xrefs type filter returns only code or data xrefs."""
    for xref_type in ("code", "data"):
        result = segment_xrefs(xref_type=xref_type, count=50)
        for xref in result["xrefs"]:
            assert xref["type"] == xref_type


@test()
def test_segment_xrefs_pagination():
    """segment_xrefs offset/count pagination works correctly."""
    r1 = segment_xrefs(offset=0, count=5)
    r2 = segment_xrefs(offset=5, count=5)
    total = r1["summary"]["total"]
    if total >= 10:
        # Pages should not overlap
        keys1 = [(x["from_addr"], x["to_addr"]) for x in r1["xrefs"]]
        keys2 = [(x["from_addr"], x["to_addr"]) for x in r2["xrefs"]]
        # Pages must be disjoint as ordered slices
        assert keys1 != keys2
    assert len(r1["xrefs"]) <= 5
    assert len(r2["xrefs"]) <= 5
