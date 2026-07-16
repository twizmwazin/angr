"""Type stubs for ``angr.rustylib.claripy.ast.bits``.

``Bits`` is the shared base class of the sized AST sorts (``BV`` and
``FP``). It adds no members of its own.
"""

from angr.rustylib.claripy.ast.base import Base

class Bits(Base): ...

__all__ = ["Bits"]
