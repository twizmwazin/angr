from __future__ import annotations

from functools import reduce
from typing import TYPE_CHECKING, Any

from .transitions import merge_transitions

if TYPE_CHECKING:
    from angr.knowledge_plugins.functions.function import Function


class CFGSliceToSink:
    """
    The representation of a slice of a CFG.
    """

    def __init__(self, target: Function, transitions: dict[int, list[int]] | None = None):
        """
        :param target:
            The targeted sink, to which every path in the slice leads.
        :param transitions:
            A mapping representing transitions in the graph.
            Indexes are source addresses and values a list of destination addresses, for which there exists a transition
            in the slice from source to destination.
        """
        self._target = target
        self._transitions = transitions or {}

    @property
    def transitions(self) -> dict[int, list[int]]:
        """
        :return: The transitions in the slice.
        """
        return self._transitions

    @property
    def transitions_as_tuples(self) -> list[tuple[int, int]]:
        """
        :return: The list of transitions as pairs of (source, destination).
        """
        return reduce(
            lambda acc, source: acc + [(source, destination) for destination in self._transitions[source]],
            self._transitions.keys(),
            [],
        )

    @property
    def target(self) -> Function:
        """
        :return:
            The targeted sink function, from which the slice is constructed.
        """
        return self._target

    @property
    def _origins(self):
        return set(self._transitions.keys())

    @property
    def _destinations(self):
        return set(reduce(lambda acc, destinations: acc + destinations, self._transitions.values(), []))

    @property
    def nodes(self) -> list[int]:
        """
        :return: The complete list of addresses present in the slice.
        """
        return list(self._origins | self._destinations)

    @property
    def entrypoints(self) -> list[int]:
        """
        Entrypoints are all source addresses that are not the destination address of any transition.

        :return: The list of entrypoints addresses.
        """
        return sorted(self._origins - self._destinations)

    def add_transitions(self, transitions: dict[int, list[int]]) -> dict[int, list[int]]:
        """
        Add the given transitions to the current slice.

        :param transitions:
            The list of transitions to be added to `self.transitions`.

        :return: Return the updated list of transitions.
        """
        self._transitions = merge_transitions(transitions, self._transitions)
        return self._transitions

    def is_empty(self) -> bool:
        """
        Test if a given slice does not contain any transition.

        :return: True if the <CFGSliceToSink> instance does not contain any transitions. False otherwise.
        """
        return not bool(self._transitions)

    def path_between(self, source: int, destination: int, visited: set[Any] | None = None) -> bool:
        """
        Check the existence of a path in the slice between two given node addresses.

        :param source: The source address.
        :param destination: The destination address.
        :param visited: Used to avoid infinite recursion if loops are present in the slice.

        :return:
            True if there is a path between the source and the destination in the CFG, False if not,
            or if we have been unable to decide (because of loops).
        """
        _visited = set() if visited is None else visited

        if source not in self._transitions or source in _visited:
            return False
        _visited.add(source)

        direct_successors = self._transitions[source]

        if destination in direct_successors:
            return True
        return any(self.path_between(s, destination, _visited) for s in direct_successors)
