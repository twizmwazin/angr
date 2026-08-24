#!/usr/bin/env python3
from __future__ import annotations

import os
from unittest import TestCase, main

import archinfo
import claripy

import angr

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "..", "..", "binaries", "tests")


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestPcodeEngine(TestCase):
    def test_shellcode(self):
        """
        Test basic CFG recovery and symbolic/concrete execution paths.
        """
        base_address = 0
        prototype = "int node_d(long)"
        code = archinfo.arch_from_id("AMD64").asm(
            """
        node_a:
            test rdi, rdi
            jz node_c
        node_b:
            mov rax, 0x1234
            jmp node_d
        node_c:
            mov rax, 0x5678
        node_d:
            ret
        """,
            base_address,
        )

        arch = archinfo.ArchPcode("x86:LE:64:default")
        angr.calling_conventions.register_default_cc(arch.name, angr.calling_conventions.SimCCSystemVAMD64)
        p = angr.load_shellcode(code, arch=arch, load_address=base_address, engine=angr.engines.UberEnginePcode)

        # Recover the CFG
        c = p.analyses.CFGFast(normalize=True)
        assert len(list(c.model.nodes())) == 4

        # Execute symbolically
        s = p.factory.call_state(base_address, prototype=prototype)
        simgr = p.factory.simulation_manager(s)
        simgr.run()
        assert sum(len(i) for i in simgr.stashes.values()) == 2
        assert {s.solver.eval(s.regs.rax) for s in simgr.deadended} == {0x1234, 0x5678}

        # Execute concretely
        callable_func = p.factory.callable(base_address, prototype=prototype, concrete_only=True)
        for input_, expected_output in [(0, 0x5678), (1, 0x1234), (0xFFFFFFFFFFFFFFFF, 0x1234)]:
            assert (callable_func(input_) == expected_output).is_true()

    def test_fauxware(self):
        """
        Test basic fauxware execution.
        """
        p = angr.Project(
            os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False, engine=angr.engines.UberEnginePcode
        )
        simgr = p.factory.simgr()
        simgr.run()

        assert sum(len(i) for i in simgr.stashes.values()) == len(simgr.deadended) == 3

        grant_paths = [s for s in simgr.deadended if b"trusted" in s.posix.dumps(1)]
        assert len(grant_paths) == 2
        assert sum(s.posix.dumps(0) == b"\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00" for s in grant_paths) == 1

        deny_paths = [s for s in simgr.deadended if b"Go away!" in s.posix.dumps(1)]
        assert len(deny_paths) == 1

    def test_riscv64_int_right_behavior(self):
        """
        Test the use of correct bitvector extension in behavior INT_RIGHT
        """
        #     beq x12, x0, 12 ; srliw x31, x5, 31
        byte_code = 0x00060663_01F2DF9B.to_bytes(8, "little")
        # abi names: t0 = x5, t6 = x31

        arch = archinfo.ArchPcode("RISCV:LE:64:default")
        p = angr.load_shellcode(byte_code, arch=arch, load_address=0, engine=angr.engines.UberEnginePcode)

        entry_state = p.factory.entry_state()
        entry_state.registers.store("t0", 2**32 - 1)  # bits 31..0 are set

        simgr = p.factory.simulation_manager(entry_state)
        simgr = simgr.step()

        # |-32bit-|
        # 111...111 >>(logical) 31 = 1

        assert simgr.active[0].regs.t6.concrete
        assert simgr.active[0].regs.t6.concrete_value == 1

    def test_callless_function_graph_consistency(self):
        binary_path = os.path.join(test_location, "x86_64", "fauxware")
        proj = angr.Project(
            binary_path,
            load_options={"auto_load_libs": False},
            engine=angr.engines.UberEnginePcode,
        )

        # Address 400550: ff 25 ca 0a 20 00 jmp *0x200aca(%rip) # 601020 <strcmp@GLIBC_2.2.5>
        # This is a PLT stub. Current limitations in the P-Code engine cause it to
        # misidentify this indirect jump as 'Ijk_Boring', leading to a disconnected
        # function graph that creates a false negative in this test.
        #
        # Since the purpose of this test is specifically to verify the CALLLESS logic
        # and not P-Code's jumpkind resolution, we manually hook this address with
        # a SimProcedure. This bypasses the engine's parsing limitations and ensures
        # the CALLLESS mechanism can correctly generate the expected FakeRet edge.
        proj.hook(0x400550, angr.SimProcedure(return_value=0), length=6)

        cfg = proj.analyses.CFGEmulated(
            keep_state=True,
            fail_fast=True,
            starts=[0x400664],  # authenticate
            state_add_options={angr.options.CALLLESS},
        )

        # For each node in cfg.graph that has outgoing edges,
        # verify that the corresponding node in function.graph also has outgoing edges.
        # A node with successors in cfg.graph but none in function.graph indicates
        # the bug where CALLLESS converts Ijk_Call to Ijk_Ret, causing
        # _update_function_transition_graph to invoke _add_return_from instead of
        # _add_fakeret_to, leaving call blocks disconnected in function.graph.
        for cfg_node in cfg.graph.nodes():
            cfg_out = cfg.graph.out_degree(cfg_node)
            if cfg_out == 0:
                continue
            # look up the function this node belongs to
            func = cfg.kb.functions.get_by_addr(cfg_node.function_address)
            if func is None:
                continue
            # find the corresponding node in function.graph
            func_node = next((n for n in func.graph.nodes() if n.addr == cfg_node.addr), None)
            if func_node is None:
                continue
            func_out = func.graph.out_degree(func_node)
            assert func_out > 0


class TestPcodeArmThumb(TestCase):
    """
    Test automatic ARM Thumb mode support in the P-Code engine. Following the convention shared with the VEX lifter,
    Thumb mode is indicated by the low bit of a code address.
    """

    @staticmethod
    def _load(code: bytes, addr: int = 0x1000):
        arch = archinfo.ArchPcode("ARM:LE:32:v7")
        return angr.load_shellcode(code, arch=arch, load_address=addr, engine=angr.engines.UberEnginePcode)

    def test_thumb_lifting_at_odd_address(self):
        # movs r0, #42 ; bx lr (Thumb)
        p = self._load(bytes.fromhex("2a207047"))

        block = p.factory.block(0x1001)
        assert block.thumb
        assert block.size == 4
        assert list(block.instruction_addrs) == [0x1001, 0x1003]
        assert [insn.mnemonic for insn in block.disassembly.insns] == ["movs", "bx"]
        assert block.vex.jumpkind == "Ijk_Ret"

        # The same bytes at an even address must still decode as ARM
        arm_block = p.factory.block(0x1000)
        assert not arm_block.thumb
        assert [insn.mnemonic for insn in arm_block.disassembly.insns] != ["movs", "bx"]

    def test_thumb_lifting_with_thumb_flag(self):
        # movs r0, #42 ; bx lr (Thumb)
        p = self._load(bytes.fromhex("2a207047"))

        block = p.factory.block(0x1000, thumb=True)
        assert block.thumb
        assert block.addr == 0x1001
        assert [insn.mnemonic for insn in block.disassembly.insns] == ["movs", "bx"]

    def test_thumb_branch_targets_keep_thumb_bit(self):
        # b 0x1008 (Thumb)
        p = self._load(bytes.fromhex("02e0"))
        irsb = p.factory.block(0x1001).vex
        assert irsb.jumpkind == "Ijk_Boring"
        assert irsb.next.con.value == 0x1009

        # beq 0x1008 ; nop (Thumb)
        p = self._load(bytes.fromhex("02d000bf"))
        irsb = p.factory.block(0x1001).vex
        assert [(src, stmt.dst) for src, _, stmt in irsb.exit_statements] == [(0x1001, 0x1009)]

        # bl 0x1008 (Thumb)
        p = self._load(bytes.fromhex("00f002f8"))
        irsb = p.factory.block(0x1001).vex
        assert irsb.jumpkind == "Ijk_Call"
        assert irsb.next.con.value == 0x1009

    def test_interworking_branch_targets(self):
        # blx 0x1010 (Thumb -> ARM: target must stay even)
        p = self._load(bytes.fromhex("00f006e8"))
        irsb = p.factory.block(0x1001).vex
        assert irsb.jumpkind == "Ijk_Call"
        assert irsb.next.con.value == 0x1010

        # blx 0x1010 (ARM -> Thumb: target must become odd)
        p = self._load(bytes.fromhex("020000fa"))
        irsb = p.factory.block(0x1000).vex
        assert irsb.jumpkind == "Ijk_Call"
        assert irsb.next.con.value == 0x1011

        # bl 0x1010 (ARM -> ARM: target must stay even)
        p = self._load(bytes.fromhex("020000eb"))
        irsb = p.factory.block(0x1000).vex
        assert irsb.jumpkind == "Ijk_Call"
        assert irsb.next.con.value == 0x1010

    def test_thumb_execution(self):
        # 0x1000: bl 0x1008    (Thumb)
        # 0x1004: nop
        # 0x1006: nop
        # 0x1008: movs r0, #42
        # 0x100a: bx lr
        p = self._load(bytes.fromhex("00f002f800bf00bf2a207047"))

        state = p.factory.blank_state(addr=0x1001)
        simgr = p.factory.simulation_manager(state)
        simgr.step()
        assert len(simgr.active) == 1
        assert simgr.active[0].addr == 0x1009  # bl target, still Thumb
        assert simgr.active[0].solver.eval(simgr.active[0].regs.lr) == 0x1005  # return address with Thumb bit

        simgr.step()
        assert len(simgr.active) == 1
        assert simgr.active[0].addr == 0x1005  # bx lr returned to Thumb code
        assert simgr.active[0].solver.eval(simgr.active[0].regs.r0) == 42

    def test_interworking_execution(self):
        # bx lr (ARM) with lr holding a Thumb address: successor must keep the Thumb bit
        p = self._load(bytes.fromhex("1eff2fe1"))
        state = p.factory.blank_state(addr=0x1000)
        state.regs.lr = claripy.BVV(0x3001, 32)
        simgr = p.factory.simulation_manager(state)
        simgr.step()
        assert len(simgr.active) == 1
        assert simgr.active[0].addr == 0x3001

        # blx 0x1010 (Thumb -> ARM): successor must be even
        p = self._load(bytes.fromhex("00f006e8"))
        simgr = p.factory.simulation_manager(p.factory.blank_state(addr=0x1001))
        simgr.step()
        assert len(simgr.active) == 1
        assert simgr.active[0].addr == 0x1010

        # blx 0x1010 (ARM -> Thumb): successor must be odd
        p = self._load(bytes.fromhex("020000fa"))
        simgr = p.factory.simulation_manager(p.factory.blank_state(addr=0x1000))
        simgr.step()
        assert len(simgr.active) == 1
        assert simgr.active[0].addr == 0x1011


if __name__ == "__main__":
    main()
