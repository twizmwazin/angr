"""Tests for the SLEIGH-based assembler module."""

import pytest

from angr.assembler import Assembler


@pytest.fixture
def x64():
    return Assembler("x86_64")


@pytest.fixture
def arm():
    return Assembler("armv7a")


@pytest.fixture
def mipsel():
    return Assembler("mipsel")


class TestDisassembly:
    def test_x86_64_nop(self, x64):
        insns = x64.disasm(b"\x90", 0x1000)
        assert len(insns) == 1
        assert insns[0].mnemonic == "NOP"
        assert insns[0].size == 1
        assert insns[0].address == 0x1000

    def test_x86_64_multi(self, x64):
        insns = x64.disasm(b"\x90\xc3", 0x1000)
        assert len(insns) == 2
        assert insns[0].mnemonic == "NOP"
        assert insns[1].mnemonic == "RET"
        assert insns[1].address == 0x1001

    def test_x86_64_count(self, x64):
        insns = x64.disasm(b"\x90\x90\x90", 0, count=2)
        assert len(insns) == 2

    def test_disasm_lite(self, x64):
        tuples = x64.disasm_lite(b"\x90\xc3", 0x1000)
        assert len(tuples) == 2
        addr, size, mnemonic, op_str = tuples[0]
        assert addr == 0x1000
        assert size == 1
        assert mnemonic == "NOP"

    def test_arm_disasm(self, arm):
        # ARM NOP: e320f000
        insns = arm.disasm(bytes([0x00, 0xF0, 0x20, 0xE3]), 0x1000)
        assert len(insns) == 1
        assert insns[0].mnemonic.lower() == "nop"

    def test_mips_disasm(self, mipsel):
        # MIPS NOP: 00000000
        insns = mipsel.disasm(b"\x00\x00\x00\x00", 0x1000)
        assert len(insns) == 1
        assert insns[0].mnemonic.lower() == "nop"


class TestAssembly:
    def test_nop(self, x64):
        assert x64.asm("NOP", 0x1000) == b"\x90"

    def test_ret(self, x64):
        assert x64.asm("RET", 0x1000) == b"\xc3"

    def test_push_rax(self, x64):
        assert x64.asm("PUSH RAX", 0x1000) == b"\x50"

    def test_pop_rax(self, x64):
        assert x64.asm("POP RAX", 0x1000) == b"\x58"

    def test_int3(self, x64):
        assert x64.asm("INT3", 0x1000) == b"\xcc"

    def test_syscall(self, x64):
        assert x64.asm("SYSCALL", 0x1000) == b"\x0f\x05"

    def test_round_trip_mov(self, x64):
        code = x64.asm("MOV EAX,EBX", 0x1000)
        insns = x64.disasm(code, 0x1000, 1)
        assert len(insns) == 1
        assert insns[0].mnemonic == "MOV"
        assert insns[0].op_str == "EAX,EBX"

    def test_round_trip_xor(self, x64):
        code = x64.asm("XOR EAX,EAX", 0x1000)
        insns = x64.disasm(code, 0x1000, 1)
        assert len(insns) == 1
        assert insns[0].mnemonic == "XOR"
        assert insns[0].op_str == "EAX,EAX"

    def test_round_trip_jmp(self, x64):
        code = x64.asm("JMP 0x1010", 0x1000)
        insns = x64.disasm(code, 0x1000, 1)
        assert len(insns) == 1
        assert insns[0].mnemonic == "JMP"

    def test_immediate_add(self, x64):
        code = x64.asm("ADD EAX,0x5", 0x1000)
        insns = x64.disasm(code, 0x1000, 1)
        assert len(insns) == 1
        assert insns[0].mnemonic == "ADD"
        assert "0x5" in insns[0].op_str

    def test_unknown_mnemonic(self, x64):
        with pytest.raises(ValueError, match="Unknown mnemonic"):
            x64.asm("FAKEINSTR", 0x1000)

    def test_empty_assembly(self, x64):
        with pytest.raises(ValueError, match="Empty assembly"):
            x64.asm("", 0x1000)


class TestAssemblyMulti:
    def test_multi_semicolons(self, x64):
        code = x64.asm_multi("NOP; RET", 0x1000)
        assert code == b"\x90\xc3"

    def test_multi_newlines(self, x64):
        code = x64.asm_multi("NOP\nRET", 0x1000)
        assert code == b"\x90\xc3"

    def test_multi_three(self, x64):
        code = x64.asm_multi("NOP; RET; PUSH RAX", 0x1000)
        assert code == b"\x90\xc3\x50"


class TestFromArch:
    def test_from_arch_amd64(self):
        import archinfo

        arch = archinfo.ArchAMD64()
        asm = Assembler.from_arch(arch)
        assert asm.architecture == "x86_64"
        assert asm.asm("NOP", 0) == b"\x90"

    def test_from_arch_x86(self):
        import archinfo

        arch = archinfo.ArchX86()
        asm = Assembler.from_arch(arch)
        assert asm.asm("NOP", 0) == b"\x90"

    def test_from_arch_arm(self):
        import archinfo

        arch = archinfo.ArchARM()
        asm = Assembler.from_arch(arch)
        insns = asm.disasm(bytes([0x00, 0xF0, 0x20, 0xE3]), 0)
        assert insns[0].mnemonic.lower() == "nop"


class TestMIPSAssembly:
    def test_nop(self, mipsel):
        code = mipsel.asm("nop", 0x1000)
        assert code == b"\x00\x00\x00\x00"


class TestInstructionRepr:
    def test_repr(self, x64):
        insns = x64.disasm(b"\x90", 0x1000)
        r = repr(insns[0])
        assert "0x1000" in r
        assert "NOP" in r

    def test_str(self, x64):
        insns = x64.disasm(b"\x90", 0x1000)
        assert str(insns[0]) == "NOP"

    def test_str_with_operands(self, x64):
        insns = x64.disasm(b"\x50", 0x1000)
        assert "PUSH" in str(insns[0])
        assert "RAX" in str(insns[0])
