"""Type stubs for ``angr.rustylib.claripy.vsa``.

Standalone VSA (value-set analysis) evaluation over AST expressions,
mirroring ``claripy.backends.vsa``.
"""

from angr.rustylib.claripy.ast.base import Base
from angr.rustylib.claripy.ast.bool import Bool
from angr.rustylib.claripy.ast.bv import BV

def reduce(expr: Base) -> Base:
    """Reduce an AST expression using VSA abstract interpretation.

    For Bool expressions: returns ``true`` if definitely true, ``false`` if
    definitely false, or a symbolic Bool if indeterminate. For BV
    expressions: returns a concrete BVV if the strided interval resolves to
    a single value, an SI if it resolves to a range, or the original
    expression if the interval is empty.
    """

def simplify(expr: Base) -> Base:
    """Simplify an expression using VSA reduction (compatibility shim for
    ``claripy.backends.vsa.simplify()``)."""

def is_true(expr: Bool) -> bool:
    """Check if a Bool expression is definitely true via VSA."""

def is_false(expr: Bool) -> bool:
    """Check if a Bool expression is definitely false via VSA."""

def has_true(expr: Bool) -> bool:
    """Check if a Bool expression could possibly be true via VSA."""

def has_false(expr: Bool) -> bool:
    """Check if a Bool expression could possibly be false via VSA."""

def min(expr: BV, signed: bool = False) -> int:
    """Get the minimum value of a BV expression via VSA."""

def max(expr: BV, signed: bool = False) -> int:
    """Get the maximum value of a BV expression via VSA."""

def eval(expr: BV, n: int) -> list[int]:
    """Evaluate a BV expression via VSA, returning up to ``n`` concrete
    values."""

def cardinality(expr: BV) -> int:
    """Get the number of possible concrete values of a BV expression via
    VSA."""

def identical(a: Base, b: Base) -> bool:
    """Check if two AST expressions are identical after VSA reduction."""

__all__ = [
    "cardinality",
    "eval",
    "has_false",
    "has_true",
    "identical",
    "is_false",
    "is_true",
    "max",
    "min",
    "reduce",
    "simplify",
]
