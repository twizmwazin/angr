# stub file for angr.rustylib.assembler

class Instruction:
    """A single disassembled instruction."""

    @property
    def address(self) -> int:
        """The address of the instruction."""

    @property
    def size(self) -> int:
        """The size of the instruction in bytes."""

    @property
    def mnemonic(self) -> str:
        """The mnemonic of the instruction (e.g., 'MOV')."""

    @property
    def op_str(self) -> str:
        """The operand string (e.g., 'EAX, 0x1')."""

    @property
    def bytes(self) -> bytes:
        """The raw bytes of the instruction."""

    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...

class SleighAssembler:
    """SLEIGH-based assembler and disassembler.

    Provides assembly and disassembly functionality using SLEIGH processor
    specifications from Ghidra, supporting all architectures that SLEIGH supports.
    """

    def __init__(self, architecture: str, processors_path: str) -> None:
        """Create a new SleighAssembler for the given architecture.

        :arg architecture: The icicle architecture string (e.g., "x86_64", "armv7a", "mips").
        :arg processors_path: Path to the SLEIGH processors directory (from pypcode).
        """

    def disasm(self, data: bytes, address: int, count: int = 0) -> list[Instruction]:
        """Disassemble bytes into a list of instructions.

        :arg data: The bytes to disassemble.
        :arg address: The base address of the first byte.
        :arg count: Maximum number of instructions to disassemble (0 for all).
        :returns: A list of Instruction objects.
        """

    def disasm_lite(
        self, data: bytes, address: int, count: int = 0
    ) -> list[tuple[int, int, str, str]]:
        """Disassemble bytes and return a list of (address, size, mnemonic, op_str) tuples.

        A lighter-weight alternative to disasm() that avoids creating Instruction objects.

        :arg data: The bytes to disassemble.
        :arg address: The base address of the first byte.
        :arg count: Maximum number of instructions to disassemble (0 for all).
        :returns: A list of (address, size, mnemonic, op_str) tuples.
        """

    def asm(self, assembly: str, address: int = 0) -> bytes:
        """Assemble a single instruction into bytes.

        Uses a constrained search over SLEIGH constructors to find the encoding
        that produces the desired disassembly output.

        :arg assembly: The assembly text (e.g., "MOV EAX, 0x1").
        :arg address: The address at which the instruction will be placed.
        :returns: The assembled bytes.
        """

    def asm_multi(self, assembly: str, address: int = 0) -> bytes:
        """Assemble multiple instructions separated by semicolons or newlines.

        :arg assembly: The assembly text with instructions separated by ';' or newlines.
        :arg address: The base address for the first instruction.
        :returns: The assembled bytes for all instructions concatenated.
        """
