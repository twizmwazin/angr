from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING, cast

from angr import claripy
from angr.claripy import Annotation

if TYPE_CHECKING:
    from angr.analyses.typehoon import typeconsts, typevars
    from angr.sim_variable import SimVariable


class StackLocationAnnotation(Annotation):
    eliminatable = False
    relocatable = False

    def __init__(self, offset):
        super().__init__()

        self.offset = offset

    def __hash__(self):
        return hash(("stack_location", self.offset))

    def __eq__(self, other):
        if not isinstance(other, StackLocationAnnotation):
            return False

        return self.offset == other.offset


class VariableSourceAnnotation(Annotation):
    eliminatable = False
    relocatable = False

    def __init__(self, block_addr, stmt_idx, ins_addr):
        super().__init__()

        self.block_addr = block_addr
        self.stmt_idx = stmt_idx
        self.ins_addr = ins_addr

    def __hash__(self):
        return hash((self.block_addr, self.stmt_idx, self.ins_addr))

    def __eq__(self, other):
        if not isinstance(other, VariableSourceAnnotation):
            return False

        return (
            self.block_addr == other.block_addr and self.stmt_idx == other.stmt_idx and self.ins_addr == other.ins_addr
        )

    @staticmethod
    def from_state(state):
        return VariableSourceAnnotation(state.scratch.bbl_addr, state.scratch.stmt_idx, state.scratch.ins_addr)


class TypeAnnotation(Annotation):
    """
    Type information that variable recovery attaches to a computed value: the type variable (or type constant) of the
    value, type constraints that have not been added to the state yet, and the variable the value was read from.

    It is eliminatable and not relocatable, so operations drop it from their results and every expression handler
    attaches the type of the value it computes. Use `typed()` to attach it and `type_of()` to read it.
    """

    __slots__ = ("_hash", "type_constraints", "typevar", "variable")

    eliminatable = True
    relocatable = False

    def __init__(
        self,
        typevar: typeconsts.TypeConstant | typevars.TypeVariable | None,
        type_constraints: frozenset[typevars.TypeConstraint],
        variable: SimVariable | None,
    ):
        self.typevar = typevar
        self.type_constraints = type_constraints
        self.variable = variable
        self._hash = hash((TypeAnnotation, typevar, type_constraints, variable))

    def __hash__(self):
        return self._hash

    def __eq__(self, other):
        return (
            type(other) is TypeAnnotation
            and self.typevar == other.typevar
            and self.type_constraints == other.type_constraints
            and self.variable == other.variable
        )

    def __repr__(self):
        return f"<TypeAnnotation {self.typevar} constraints={set(self.type_constraints)} variable={self.variable}>"


_NO_TYPE = TypeAnnotation(None, frozenset(), None)


def typed[T: claripy.ast.BV](
    data: T,
    typevar: typeconsts.TypeConstant | typevars.TypeVariable | None = None,
    type_constraints: Iterable[typevars.TypeConstraint] | None = None,
    variable: SimVariable | None = None,
) -> T:
    """
    Return `data` carrying exactly the given type information, replacing whatever type information it carried.
    """
    if data.has_annotation_type(TypeAnnotation):
        data = data.clear_annotation_type(TypeAnnotation)
    if typevar is None and not type_constraints and variable is None:
        return data
    return data.annotate(TypeAnnotation(typevar, frozenset(type_constraints or ()), variable))


def with_type_constraints[T: claripy.ast.BV](data: T, *type_constraints: typevars.TypeConstraint) -> T:
    """
    Return `data` with `type_constraints` added to the type constraints it carries.
    """
    t = type_of(data)
    return typed(data, t.typevar, t.type_constraints.union(type_constraints), t.variable)


def untyped[T: claripy.ast.BV](data: T) -> T:
    """
    Return `data` without type information, for storing it in the state.
    """
    if data.has_annotation_type(TypeAnnotation):
        return data.clear_annotation_type(TypeAnnotation)
    return data


def type_of(data: claripy.ast.BV) -> TypeAnnotation:
    """
    Return the type information `data` carries. Values without any carry no type variable, no constraints, and no
    variable.
    """
    annotation = data.get_annotation(TypeAnnotation)
    return cast(TypeAnnotation, annotation) if annotation is not None else _NO_TYPE
