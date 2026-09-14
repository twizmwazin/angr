"""Type stubs for ``angr.rustylib.claripy.ast.bits``."""

from angr.rustylib.claripy.ast.base import Base

class Bits(Base):
    def size(self) -> int: ...
    def __len__(self) -> int: ...
    @property
    def length(self) -> int: ...

__all__ = ["Bits"]
