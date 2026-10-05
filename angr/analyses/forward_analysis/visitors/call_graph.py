from __future__ import annotations

from typing import TYPE_CHECKING

from angr.utils.graph import GraphUtils

from .graph import GraphVisitor

if TYPE_CHECKING:
    import networkx


class CallGraphVisitor(GraphVisitor):
    """
    :param callgraph:
    """

    def __init__(self, callgraph: networkx.DiGraph):
        super().__init__()
        self.callgraph = callgraph

        self.reset()

    def successors(self, node):
        return list(self.callgraph.successors(node))

    def predecessors(self, node):
        return list(self.callgraph.predecessors(node))

    def sort_nodes(self, nodes=None):
        sorted_nodes = GraphUtils.quasi_topological_sort_nodes(self.callgraph)

        if nodes is not None:
            sorted_nodes = [n for n in sorted_nodes if n in set(nodes)]

        return sorted_nodes
