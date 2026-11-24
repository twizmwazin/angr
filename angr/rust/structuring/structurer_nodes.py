from __future__ import annotations

from collections import OrderedDict

from angr import ailment, claripy
from angr.ailment.statement import Statement
from angr.analyses.decompiler.structurer_nodes import INDENT_DELTA, BaseNode, Node, SequenceNode
from angr.rust.sim_type import EnumVariant


class PatternMatchNode[C: claripy.ast.Bool | ailment.Expr.Expression](BaseNode[C]):
    """A Rust match expression node in the structured code tree."""

    __slots__ = (
        "arms",
        "default_node",
        "scrutinee",
    )

    def __init__(
        self,
        scrutinee,
        arms: OrderedDict[tuple[EnumVariant, tuple[Statement]], SequenceNode[C]],
        default_node: Node[C] | None,
        addr=None,
    ):
        super().__init__(addr)
        self.scrutinee = scrutinee
        self.arms: OrderedDict[tuple[EnumVariant, tuple[Statement]], SequenceNode[C]] = arms
        self.default_node: Node[C] | None = default_node

    def dbg_repr(self, indent=0):
        indent_str = indent * " "
        s = indent_str + f"match {self.scrutinee} {{\n"
        for (variant, _), node in self.arms.items():
            s += indent_str + f"{variant} => {{\n" + node.dbg_repr(indent + INDENT_DELTA) + "\n},\n"
        return s


class IfLetNode[C: claripy.ast.Bool | ailment.Expr.Expression](BaseNode[C]):
    """A Rust if-let expression node in the structured code tree."""

    __slots__ = (
        "false_node",
        "pattern",
        "scrutinee",
        "true_node",
    )

    def __init__(
        self,
        pattern,
        scrutinee,
        true_node: Node[C],
        false_node: Node[C] | None = None,
        addr=None,
    ):
        super().__init__(addr)
        self.pattern = pattern
        self.scrutinee = scrutinee
        self.true_node: Node[C] = true_node
        self.false_node: Node[C] | None = false_node

    def dbg_repr(self, indent=0):
        indent_str = indent * " "
        s = indent_str + f"if let {self.pattern} {{\n"
        s += indent_str + self.true_node.dbg_repr(indent + INDENT_DELTA) + "\n}"
        if self.false_node:
            s += ", else {\n" + self.false_node.dbg_repr(indent + INDENT_DELTA) + "\n}"
        return s
