"""SLEIGH-based assembler and disassembler module.

This module provides assembly and disassembly functionality using SLEIGH
processor specifications from Ghidra (via icicle-emu), offering similar
functionality to keystone and capstone.

Usage::

    from angr.assembler import Assembler

    # Create from an angr Arch object
    asm = Assembler.from_arch(project.arch)

    # Disassemble
    instructions = asm.disasm(b"\\x90\\x90", 0x1000)
    for insn in instructions:
        print(f"{insn.address:#x}: {insn.mnemonic} {insn.op_str}")

    # Assemble
    code = asm.asm("NOP", 0x1000)

    # Or create directly with an architecture string
    asm = Assembler("x86_64")
"""

from __future__ import annotations

import logging
import os

import pypcode
from archinfo import Arch, ArchARMCortexM, ArchPcode, Endness

from angr.rustylib.assembler import Instruction, SleighAssembler

log = logging.getLogger(__name__)

PROCESSORS_DIR = os.path.join(os.path.dirname(pypcode.__file__), "processors")

# Re-export Instruction from the Rust module
__all__ = ["Assembler", "Instruction"]


def _arch_to_icicle(arch: Arch) -> str | None:
    """Convert an angr architecture to an icicle architecture string."""
    if isinstance(arch, ArchARMCortexM) or (
        isinstance(arch, ArchPcode) and arch.pcode_arch == "ARM:LE:32:Cortex"
    ):
        return "armv7m"
    if arch.linux_name == "arm":
        return "armv7a" if arch.memory_endness == Endness.LE else "armeb"
    return arch.linux_name


class Assembler:
    """SLEIGH-based assembler and disassembler.

    Provides capstone-like disassembly and keystone-like assembly using
    Ghidra's SLEIGH processor specifications. Supports all architectures
    that SLEIGH supports.
    """

    def __init__(
        self,
        architecture: str,
        processors_path: str | None = None,
    ) -> None:
        """Create a new Assembler for the given architecture.

        :param architecture: The icicle architecture string (e.g., "x86_64",
            "x86", "armv7a", "mips", "mipsel", "aarch64", "powerpc").
        :param processors_path: Path to the SLEIGH processors directory. If
            None, uses the processors bundled with pypcode.
        """
        if processors_path is None:
            processors_path = PROCESSORS_DIR
        self._inner = SleighAssembler(architecture, processors_path)
        self._architecture = architecture

    @classmethod
    def from_arch(cls, arch: Arch, processors_path: str | None = None) -> Assembler:
        """Create an Assembler from an angr Arch object.

        :param arch: An angr architecture object.
        :param processors_path: Path to the SLEIGH processors directory. If
            None, uses the processors bundled with pypcode.
        :returns: A new Assembler instance.
        """
        icicle_arch = _arch_to_icicle(arch)
        if icicle_arch is None:
            raise ValueError(f"Unsupported architecture: {arch}")
        return cls(icicle_arch, processors_path)

    @property
    def architecture(self) -> str:
        """The icicle architecture string."""
        return self._architecture

    def disasm(
        self,
        data: bytes,
        address: int = 0,
        count: int = 0,
    ) -> list[Instruction]:
        """Disassemble bytes into a list of instructions.

        Similar to capstone's disasm() method.

        :param data: The bytes to disassemble.
        :param address: The base address of the first byte.
        :param count: Maximum number of instructions to disassemble (0 for all).
        :returns: A list of Instruction objects with address, size, mnemonic,
            op_str, and bytes attributes.
        """
        return self._inner.disasm(data, address, count)

    def disasm_lite(
        self,
        data: bytes,
        address: int = 0,
        count: int = 0,
    ) -> list[tuple[int, int, str, str]]:
        """Disassemble bytes and return lightweight tuples.

        Similar to capstone's disasm_lite() method.

        :param data: The bytes to disassemble.
        :param address: The base address of the first byte.
        :param count: Maximum number of instructions to disassemble (0 for all).
        :returns: A list of (address, size, mnemonic, op_str) tuples.
        """
        return self._inner.disasm_lite(data, address, count)

    def asm(
        self,
        assembly: str,
        address: int = 0,
    ) -> bytes:
        """Assemble a single instruction into bytes.

        Similar to keystone's asm() method.

        :param assembly: The assembly text (e.g., "MOV EAX, 0x1").
        :param address: The address at which the instruction will be placed.
        :returns: The assembled bytes.
        :raises ValueError: If the assembly string cannot be assembled.
        """
        return bytes(self._inner.asm(assembly, address))

    def asm_multi(
        self,
        assembly: str,
        address: int = 0,
    ) -> bytes:
        """Assemble multiple instructions separated by semicolons or newlines.

        :param assembly: The assembly text with instructions separated by
            ';' or newlines.
        :param address: The base address for the first instruction.
        :returns: The assembled bytes for all instructions concatenated.
        """
        return bytes(self._inner.asm_multi(assembly, address))
