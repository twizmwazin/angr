"""Type stubs for ``angr.rustylib.claripy.fp``.

Compatibility module mirroring claripy's ``claripy.fp``: the rounding
mode and float sort types plus the standard sort constants.
"""

from angr.rustylib.claripy.ast.fp import RM as RM
from angr.rustylib.claripy.ast.fp import FSort as FSort

FSORT_FLOAT: FSort
FSORT_DOUBLE: FSort

__all__ = ["FSORT_DOUBLE", "FSORT_FLOAT", "RM", "FSort"]
