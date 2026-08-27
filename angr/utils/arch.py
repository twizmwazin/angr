from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from archinfo import Arch, RegisterOffset


def get_sp_offset(arch: Arch) -> RegisterOffset | None:
    """
    Get the offset of the stack pointer register in the register file of an architecture.

    The stack pointer is looked up in the architecture's register mapping under its canonical name
    "sp"; architectures without a stack pointer register (e.g., Soot) have no such mapping.

    :param arch:    The architecture to query.
    :return:        The register file offset of the stack pointer, or None if the architecture does
                    not define a stack pointer register.
    """
    sp = arch.registers.get("sp")
    return sp[0] if sp is not None else None
