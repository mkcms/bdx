from __future__ import annotations

from abc import ABC, abstractmethod
from collections import deque
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Optional

import astar
from pygraphviz import AGraph

from bdx import debug, detail_log, trace
from bdx.binary import Symbol
from bdx.index import SymbolIndex, sigint_catcher


class GraphAlgorithm(Enum):
    """Enumeration for graph search algorithms."""

    BFS = "BFS"
    DFS = "DFS"
    ASTAR = "ASTAR"


def _get_neighbors(index: SymbolIndex, symbol: Symbol) -> set[Symbol]:
    cache = getattr(index, "__neighbors_cache", None)
    if cache is None:
        cache = dict()
        setattr(index, "__neighbors_cache", cache)

    try:
        return cache[symbol]
    except KeyError:
        query = index.schema["relocations"].make_query(symbol.name)
        res = set(index.search(query))

        # If `symbol' is "func" we could have matched symbols that
        # have a relocation to "some_func".  Filter out the results to
        # make sure we match the symbol exactly.
        res = set([x for x in res if symbol.name in x.relocations])

        cache[symbol] = res
        return res


class Searcher(ABC):
    """Breadth-first search."""

    def __init__(
        self,
        index: SymbolIndex,
        should_quit: Callable[[], bool],
        on_symbol_visited: Callable[[], Any],
    ):
        """Initialize this searcher for given index.

        Args:
            index: The symbol index to search in.
            should_quit: Function returning True if search should stop.
            on_symbol_visited: Called on each symbol visited.

        """
        self.index = index
        self.should_quit = should_quit
        self.on_symbol_visited = on_symbol_visited

    @abstractmethod
    def search(
        self, start: Symbol, goal: set[Symbol]
    ) -> Optional[list[Symbol]]:
        """Return a path from ``start`` to ``goal``, if it exists."""
        pass


class BFS(Searcher):
    """Breadth-first search."""

    def search(
        self, start: Symbol, goal: set[Symbol]
    ) -> Optional[list[Symbol]]:
        """Return a path from ``start`` to ``goal``, if it exists."""
        queue: deque[tuple[Symbol, list[Symbol]]] = deque([(start, [])])

        visited = set()

        while queue and not self.should_quit():
            symbol, came_from = queue.popleft()
            visited.add(symbol)

            detail_log(
                "Visit: {} From: {} (depth {})",
                symbol.name,
                came_from[0].name if came_from else None,
                len(came_from),
            )

            self.on_symbol_visited()

            if symbol in goal and came_from:
                return [*came_from, symbol]

            relocs = [
                (sym, [*came_from, symbol])
                for sym in _get_neighbors(self.index, symbol)
                if sym not in visited
            ]

            queue.extend(relocs)

        return None


class DFS(Searcher):
    """Depth-first search."""

    def search(
        self, start: Symbol, goal: set[Symbol]
    ) -> Optional[list[Symbol]]:
        """Return a path from ``start`` to ``goal``, if it exists."""
        queue: deque[tuple[Symbol, list[Symbol]]] = deque([(start, [])])

        visited = set()

        while queue and not self.should_quit():
            symbol, came_from = queue.popleft()
            visited.add(symbol)

            detail_log(
                "Visit: {} From: {} (depth {})",
                symbol.name,
                came_from[0].name if came_from else None,
                len(came_from),
            )

            self.on_symbol_visited()

            if symbol in goal and came_from:
                return [*came_from, symbol]

            relocs = [
                (sym, [*came_from, symbol])
                for sym in _get_neighbors(self.index, symbol)
                if sym not in visited
            ]

            queue.extendleft(relocs)

        return None


class ASTAR(Searcher, astar.AStar):
    """Wrapper for the A* algorithm."""

    class Interrupt(BaseException):
        """Used to stop the search gracefully."""

    def search(
        self, start: Symbol, goal: set[Symbol]
    ) -> Optional[list[Symbol]]:
        """Return a path from ``start`` to ``goal``, if it exists."""
        try:
            res = self.astar(start, goal)
        except ASTAR.Interrupt:
            return None

        if res:
            return list(res)

        return None

    def neighbors(self, node: Symbol) -> set[Symbol]:
        """Get all the neighbors of given node."""
        if self.should_quit():
            raise ASTAR.Interrupt
        self.on_symbol_visited()
        return _get_neighbors(self.index, node)

    def distance_between(self, n1, n2) -> float:
        """Get the distance between two nodes."""
        if self.should_quit():
            raise ASTAR.Interrupt
        return 1

    def is_goal_reached(self, current: Symbol, goal: Iterable[Symbol]) -> bool:
        """Return true if the given node is the end node."""
        if self.should_quit():
            raise ASTAR.Interrupt
        return current in goal

    def heuristic_cost_estimate(
        self, current: Symbol, goal: Iterable[Symbol]
    ) -> float:
        """Calculate the A* heuristic for given node and goal."""
        if self.should_quit():
            raise ASTAR.Interrupt
        # TODO: Use actual heuristic
        return 1


def _generate_paths(
    index: SymbolIndex,
    start_set: set[Symbol],
    goal_set: set[Symbol],
    algo: GraphAlgorithm,
    should_quit: Callable[[], bool],
    on_progress: Callable[[int, int], Any],
    on_symbol_visited: Callable[[], Any],
) -> Iterator[list[Symbol]]:

    # Swap the sets as we actually search the _references_ of a
    # symbol, not "what it references".  We reverse the paths later.
    start_set, goal_set = goal_set, start_set

    searcher: Optional[Searcher] = None

    if algo == GraphAlgorithm.BFS:
        searcher = BFS(index, should_quit, on_symbol_visited)
    elif algo == GraphAlgorithm.DFS:
        searcher = DFS(index, should_quit, on_symbol_visited)
    elif algo == GraphAlgorithm.ASTAR:
        searcher = ASTAR(index, should_quit, on_symbol_visited)
    else:
        msg = f"Unknown algorithm: {algo}"
        raise ValueError(msg)

    for i, start in enumerate(start_set):
        path = searcher.search(start, goal_set)

        on_progress(i + 1, len(start_set))

        if not path:
            continue

        path.reverse()

        yield path


def generate_graph(
    index_path: Path,
    start_query: str,
    goal_query: str,
    algo: GraphAlgorithm = GraphAlgorithm.ASTAR,
    num_routes: Optional[int] = 1,
    on_progress: Callable[[int, int], Any] = lambda x, y: None,
    on_symbol_visited: Callable[[], Any] = lambda: None,
    on_route_found: Callable[[], Any] = lambda: None,
) -> AGraph:
    """Generate a graph from results of one query to another.

    The graph is generated by searching all paths from nodes matching
    ``start_query`` to nodes matching ``goal_query``.

    Args:
        index_path: The index to generate a graph for.
        start_query: We will start from symbols matching this query.
        goal_query: We will try to reach symbols matching this query
        algo: The algorithm to use.
        num_routes: Exit after finding that many routes
            (if None, generate them infinitely).
        on_progress: Progress callback called with (NUM_DONE, NUM_TOTAL) args.
        on_symbol_visited: Called for each symbol visited.
        on_route_found: Called after a single route is found.

    """
    index = SymbolIndex.open(index_path, readonly=True)
    with sigint_catcher() as interrupted, index:
        graph = AGraph(
            beautify=True,
            overlap=False,
            splines=True,
            rankdir="LR",
        )

        start_subgraph: AGraph = graph.add_subgraph(
            name="cluster_start_query",
            label=f'Matching start query "{start_query}"',
            style="filled",
        )
        goal_subgraph: AGraph = graph.add_subgraph(
            name="cluster_goal_query",
            label=f'Matching goal query "{goal_query}"',
            style="filled",
        )

        nodes = set()

        if num_routes is None:
            num_routes = 9999999999999

        start_query_set = set(index.search(start_query))
        goal_query_set = set(index.search(goal_query))

        debug(
            "Start set has length {}, goal set has length {}",
            len(start_query_set),
            len(goal_query_set),
        )

        if not goal_query_set or not start_query_set:
            return graph

        def add_node(graph: AGraph, symbol: Symbol):
            graph.add_node(symbol.name)
            node = graph.get_node(symbol.name)
            attr = node.attr  # pyright: ignore
            attr["label"] = symbol.demangled or symbol.name
            attr["bdx.path"] = symbol.path
            attr["bdx.address"] = symbol.address
            attr["bdx.section"] = symbol.section
            attr["bdx.size"] = symbol.size

        for i, path in enumerate(
            _generate_paths(
                index,
                start_query_set,
                goal_query_set,
                algo,
                interrupted,
                on_progress,
                on_symbol_visited,
            )
        ):
            on_route_found()

            trace(
                "Found path {} -> ... -> {} of length {}",
                path[0].name,
                path[-1].name,
                len(path),
            )

            nodes.update(path)

            for prev, next in zip(path, path[1:], strict=False):
                graph.add_edge(
                    prev.name,
                    next.name,
                    dir="forward",
                )

            if i + 1 == num_routes:
                break

        for node in nodes:
            if node in goal_query_set:
                add_node(goal_subgraph, node)
            elif node in start_query_set:
                add_node(start_subgraph, node)
            else:
                add_node(graph, node)

    return graph
