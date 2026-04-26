"""Path enumeration and dominator tree tools.

Provides two MCP tools:
- find_paths: BFS path enumeration between basic blocks within a function
- dominator_tree: Compute dominator tree for a function's CFG
"""

from collections import deque
from typing import Annotated, NotRequired, TypedDict

import idaapi
import ida_funcs
import ida_gdl

from .rpc import tool
from .sync import idasync, IDAError
from .utils import parse_address


# ============================================================================
# TypedDicts
# ============================================================================


class FindPathsResult(TypedDict, total=False):
    func: str
    src: str
    dst: str
    paths: list[list[str]]
    count: int
    truncated: bool
    error: str


class DominatorTreeResult(TypedDict, total=False):
    func: str
    dominators: dict[str, str | None]
    error: str


# ============================================================================
# Helpers
# ============================================================================


def _resolve_func_and_ea(func_addr: str) -> tuple[ida_funcs.func_t, int]:
    """Resolve function address string to (func_t, start_ea)."""
    ea = parse_address(func_addr)
    func = idaapi.get_func(ea)
    if func is None:
        raise IDAError(f"No function found at {func_addr}")
    return func, func.start_ea


def _build_cfg(func: ida_funcs.func_t) -> dict[int, list[int]]:
    """Return adjacency list {bb_start: [successor_bb_start, ...]} for all blocks."""
    adj: dict[int, list[int]] = {}
    for block in idaapi.FlowChart(func):
        adj[block.start_ea] = [s.start_ea for s in block.succs()]
    return adj


def _find_block_containing(func: ida_funcs.func_t, ea: int) -> int | None:
    """Return the start address of the basic block containing ea, or None."""
    for block in idaapi.FlowChart(func):
        if block.start_ea <= ea < block.end_ea:
            return block.start_ea
    return None


# ============================================================================
# Tools
# ============================================================================


@tool
@idasync
def find_paths(
    func: Annotated[str, "Function address or name containing the basic blocks"],
    src: Annotated[str, "Source basic block address (or any address within the block)"],
    dst: Annotated[str, "Destination basic block address (or any address within the block)"],
    max_paths: Annotated[int, "Maximum number of paths to return (default: 50, max: 200)"] = 50,
) -> FindPathsResult:
    """Enumerate all paths between two basic blocks within a function using BFS.

    Finds all acyclic paths from the basic block containing 'src' to the basic
    block containing 'dst' in the function's control-flow graph. Each path is a
    list of basic block start addresses (as hex strings).

    Caps output at max_paths to avoid combinatorial blowup on large functions.
    Returns 'truncated: true' if the actual number of paths exceeds max_paths.

    Useful for reachability analysis, taint tracing, and identifying code paths
    between security-relevant blocks (e.g. allocation → use, check → bypass).
    """
    if max_paths <= 0 or max_paths > 200:
        max_paths = 200

    try:
        fn, _fn_start = _resolve_func_and_ea(func)

        src_ea = parse_address(src)
        dst_ea = parse_address(dst)

        src_bb = _find_block_containing(fn, src_ea)
        if src_bb is None:
            return FindPathsResult(
                func=func, src=src, dst=dst, paths=[], count=0,
                error=f"Source address {src} is not within function {func}",
            )

        dst_bb = _find_block_containing(fn, dst_ea)
        if dst_bb is None:
            return FindPathsResult(
                func=func, src=src, dst=dst, paths=[], count=0,
                error=f"Destination address {dst} is not within function {func}",
            )

        adj = _build_cfg(fn)

        # BFS over paths (not nodes) to enumerate all acyclic paths
        # State: (current_bb, path_so_far_as_frozenset_for_cycle_detection, path_list)
        # Use deque for BFS; bound by max_paths
        found_paths: list[list[str]] = []
        truncated = False

        # Queue entries: (current_bb_start, visited_set, path_list)
        queue: deque[tuple[int, frozenset[int], list[int]]] = deque()
        queue.append((src_bb, frozenset([src_bb]), [src_bb]))

        while queue and not truncated:
            current, visited, path = queue.popleft()

            if current == dst_bb:
                if len(found_paths) >= max_paths:
                    truncated = True
                    break
                found_paths.append([hex(bb) for bb in path])
                # Don't extend further from dst — path is complete
                continue

            for successor in adj.get(current, []):
                if successor in visited:
                    # Avoid cycles
                    continue
                new_visited = visited | {successor}
                new_path = path + [successor]
                queue.append((successor, new_visited, new_path))

        return FindPathsResult(
            func=func,
            src=hex(src_bb),
            dst=hex(dst_bb),
            paths=found_paths,
            count=len(found_paths),
            truncated=truncated,
        )
    except IDAError as e:
        return FindPathsResult(func=func, src=src, dst=dst, paths=[], count=0, error=str(e))
    except Exception as e:
        return FindPathsResult(func=func, src=src, dst=dst, paths=[], count=0, error=str(e))


@tool
@idasync
def dominator_tree(
    func: Annotated[str, "Function address or name to compute dominator tree for"],
) -> DominatorTreeResult:
    """Compute the dominator tree for a function's control-flow graph.

    Uses ida_gdl.calc_dominators() to compute immediate dominators for each
    basic block. The entry block dominates all others; each block maps to its
    immediate dominator (the closest block that dominates it on every path from
    entry).

    Returns {bb_addr: dominator_bb_addr} where the entry block maps to null
    (it has no dominator). Addresses are hex strings.

    Useful for path feasibility analysis, identifying post-dominator-based
    sanitizer checks, and computing program slices.
    """
    try:
        fn, fn_start = _resolve_func_and_ea(func)

        # Build list of all blocks for index mapping
        blocks = list(idaapi.FlowChart(fn))
        if not blocks:
            return DominatorTreeResult(func=func, dominators={})

        # Map start_ea -> block index
        ea_to_idx: dict[int, int] = {b.start_ea: i for i, b in enumerate(blocks)}

        # ida_gdl.calc_dominators returns a list of immediate dominator indices
        # indexed by block index. Entry block (index 0) dominates itself / has no parent.
        try:
            # calc_dominators(graph) -> list[int] of length block_count
            # where result[i] = index of immediate dominator of block i
            # For the entry block, result[0] == 0 (self-reference)
            dom_list = ida_gdl.calc_dominators(idaapi.FlowChart(fn))
        except Exception:
            dom_list = None

        dominators: dict[str, str | None] = {}

        if dom_list is not None and len(dom_list) == len(blocks):
            for i, block in enumerate(blocks):
                idom_idx = dom_list[i]
                if i == 0 or idom_idx == i:
                    # Entry block or self — no dominator
                    dominators[hex(block.start_ea)] = None
                else:
                    if 0 <= idom_idx < len(blocks):
                        dominators[hex(block.start_ea)] = hex(blocks[idom_idx].start_ea)
                    else:
                        dominators[hex(block.start_ea)] = None
        else:
            # Fallback: compute dominators manually via iterative dataflow
            n = len(blocks)
            entry_ea = fn_start

            # Find entry index
            entry_idx = 0
            for i, b in enumerate(blocks):
                if b.start_ea == entry_ea:
                    entry_idx = i
                    break

            # Build successor index map
            adj_idx: dict[int, list[int]] = {}
            for i, b in enumerate(blocks):
                adj_idx[i] = [ea_to_idx[s.start_ea] for s in b.succs() if s.start_ea in ea_to_idx]

            # Build predecessor index map
            pred_idx: dict[int, list[int]] = {i: [] for i in range(n)}
            for i, succs in adj_idx.items():
                for s in succs:
                    pred_idx[s].append(i)

            # Classic iterative dominator algorithm (Cooper et al.)
            # dom[i] = immediate dominator index, -1 = undefined
            dom = [-1] * n
            dom[entry_idx] = entry_idx

            def _intersect(b1: int, b2: int, post_order: list[int]) -> int:
                po_map = {v: i for i, v in enumerate(post_order)}
                while b1 != b2:
                    while po_map[b1] < po_map[b2]:
                        b1 = dom[b1]
                    while po_map[b2] < po_map[b1]:
                        b2 = dom[b2]
                return b1

            # Compute post-order traversal
            post_order: list[int] = []
            visited_set: set[int] = set()

            def _dfs(node: int):
                if node in visited_set:
                    return
                visited_set.add(node)
                for s in adj_idx.get(node, []):
                    _dfs(s)
                post_order.append(node)

            _dfs(entry_idx)

            changed = True
            while changed:
                changed = False
                # Reverse post-order
                for b in reversed(post_order):
                    if b == entry_idx:
                        continue
                    preds = [p for p in pred_idx[b] if dom[p] != -1]
                    if not preds:
                        continue
                    new_idom = preds[0]
                    for p in preds[1:]:
                        new_idom = _intersect(new_idom, p, post_order)
                    if dom[b] != new_idom:
                        dom[b] = new_idom
                        changed = True

            for i, block in enumerate(blocks):
                if i == entry_idx or dom[i] == i or dom[i] == -1:
                    dominators[hex(block.start_ea)] = None
                else:
                    dominators[hex(block.start_ea)] = hex(blocks[dom[i]].start_ea)

        return DominatorTreeResult(func=func, dominators=dominators)
    except IDAError as e:
        return DominatorTreeResult(func=func, dominators={}, error=str(e))
    except Exception as e:
        return DominatorTreeResult(func=func, dominators={}, error=str(e))
