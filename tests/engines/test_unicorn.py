#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

__package__ = __package__ or "tests.engines"  # pylint:disable=redefined-builtin

import gc
import os
import pickle
import re
import unittest

import angr
from angr import claripy
from angr import options as so
from angr.state_plugins.unicorn_engine import _UC_NATIVE, _check_vex_archinfo_layout
from tests.common import bin_location, minimal_project

test_location = os.path.join(bin_location, "tests")


def _remove_addr_from_trace_item(trace_item_str):
    m = re.match(r"(<\S+ \S+) from .*(:[\s\S]+)", trace_item_str)
    if m is None:
        return None
    return m.group(1) + m.group(2)


def _arch_regs(arch):
    if arch == "amd64":
        return ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip", "flags"]
    return [f"r{i}" for i in range(13)] + ["sp", "lr", "pc", "flags", "itstate"]


def _compare_trace(trace, expected):
    assert len(trace) == len(expected)

    for trace_item, expected_str in zip(trace, expected):
        trace_item_str = str(trace_item)
        if trace_item_str.startswith("<SimProcedure"):
            # we do not care if addresses of SimProcedures match, since they are not allocated in a deterministic way
            trace_item_str = _remove_addr_from_trace_item(trace_item_str)
            expected_str = _remove_addr_from_trace_item(expected_str)

        assert trace_item_str == expected_str


class TestUnicorn(unittest.TestCase):
    def test_stops(self):
        p = angr.Project(os.path.join(test_location, "i386", "uc_stop"), auto_load_libs=False)

        # test STOP_NORMAL, STOP_STOPPOINT
        s_normal = p.factory.entry_state(args=["a"], add_options=so.unicorn)
        s_normal.unicorn.max_steps = 100
        pg_normal = p.factory.simulation_manager(s_normal).run()
        p_normal = pg_normal.one_deadended
        _compare_trace(
            p_normal.history.descriptions,
            [
                "<Unicorn (STOP_STOPPOINT after 4 steps) from _start+0x0 in uc_stop (0x8048340): 1 sat>",
                "<SimProcedure __libc_start_main from 0x8100004 (__libc_start_main+0x0 in extern-address space (0x4)): 1 sat>",
                "<Unicorn (STOP_STOPPOINT after 14 steps) from __libc_csu_init+0x0 in uc_stop (0x8048650): 1 sat>",
                "<SimProcedure __libc_start_main from 0x820104c (__libc_start_main.after_init+0x0 in extern-address space (0x104c)): 1 sat>",
                "<Unicorn (STOP_NORMAL after 100 steps) from main+0x0 in uc_stop (0x80485b5): 1 sat>",
                "<Unicorn (STOP_STOPPOINT after 12 steps) from stop_normal+0x19 in uc_stop (0x804846f): 1 sat>",
                "<SimProcedure __libc_start_main from 0x8201050 (__libc_start_main.after_main+0x0 in extern-address space (0x1050)): 1 sat>",
            ],
        )

        s_normal_angr = p.factory.entry_state(args=["a"])
        pg_normal_angr = p.factory.simulation_manager(s_normal_angr).run()
        p_normal_angr = pg_normal_angr.one_deadended
        assert p_normal_angr.history.bbl_addrs.hardcopy == p_normal.history.bbl_addrs.hardcopy

        # test STOP_STOPPOINT on an address that is not a basic block start
        s_stoppoints = p.factory.call_state(
            p.loader.find_symbol("main").rebased_addr, 1, angr.PointerWrapper([]), add_options=so.unicorn
        )

        # this address is right before/after the bb for the stop_normal() function ends
        # we should not stop there, since that code is never hit
        stop_fake = [0x0804847C, 0x08048454]

        # this is an address inside main that is not the beginning of a basic block. we should stop here
        stop_in_bb = 0x08048638
        stop_bb = 0x08048633  # basic block of the above address
        pg_stoppoints = p.factory.simulation_manager(s_stoppoints).run(n=1, extra_stop_points=[*stop_fake, stop_in_bb])
        assert len(pg_stoppoints.active) == 1
        p_stoppoints = pg_stoppoints.one_active
        assert p_stoppoints.addr == stop_bb
        _compare_trace(
            p_stoppoints.history.descriptions,
            ["<Unicorn (STOP_STOPPOINT after 111 steps) from main+0x0 in uc_stop (0x80485b5): 1 sat>"],
        )

        # test STOP_SYMBOLIC_READ_SYMBOLIC_TRACKING_DISABLED
        s_symbolic_read_tracking_disabled = p.factory.entry_state(
            args=["a", "a"],
            add_options=so.unicorn,
            remove_options={so.UNICORN_SYM_REGS_SUPPORT},
        )
        pg_symbolic_read_tracking_disabled = p.factory.simulation_manager(s_symbolic_read_tracking_disabled).run()
        p_symbolic_read_tracking_disabled = pg_symbolic_read_tracking_disabled.one_deadended
        _compare_trace(
            p_symbolic_read_tracking_disabled.history.descriptions,
            [
                "<Unicorn (STOP_STOPPOINT after 4 steps) from _start+0x0 in uc_stop (0x8048340): 1 sat>",
                "<SimProcedure __libc_start_main from 0x8100004 (__libc_start_main+0x0 in extern-address space (0x4)): 1 sat>",
                "<Unicorn (STOP_STOPPOINT after 14 steps) from __libc_csu_init+0x0 in uc_stop (0x8048650): 1 sat>",
                "<SimProcedure __libc_start_main from 0x820104c (__libc_start_main.after_init+0x0 in extern-address space (0x104c)): 1 sat>",
                "<Unicorn (STOP_SYMBOLIC_READ_SYMBOLIC_TRACKING_DISABLED after 7 steps) from main+0x0 in uc_stop (0x80485b5): 1 sat>",
                "<IRSB from stop_symbolic_read_symbolic_tracking_disabled+0xe in uc_stop (0x804848a): 1 sat 3 unsat>",
                "<Unicorn (STOP_STOPPOINT after 3 steps) from stop_symbolic_read_symbolic_tracking_disabled+0x3f in uc_stop (0x80484bb): 1 sat>",
                "<SimProcedure __libc_start_main from 0x8201050 (__libc_start_main.after_main+0x0 in extern-address space (0x1050)): 1 sat>",
            ],
        )

        s_symbolic_read_tracking_disabled_angr = p.factory.entry_state(args=["a", "a"])
        pg_symbolic_read_tracking_disabled_angr = p.factory.simulation_manager(
            s_symbolic_read_tracking_disabled_angr
        ).run()
        p_symbolic_read_tracking_disabled_angr = pg_symbolic_read_tracking_disabled_angr.one_deadended
        assert (
            p_symbolic_read_tracking_disabled_angr.history.bbl_addrs.hardcopy
            == p_symbolic_read_tracking_disabled.history.bbl_addrs.hardcopy
        )

        # test STOP_SEGFAULT
        s_segfault = p.factory.entry_state(
            args=["a", "a", "a", "a", "a", "a", "a"],
            add_options=so.unicorn | {so.STRICT_PAGE_ACCESS, so.ENABLE_NX},
        )
        pg_segfault = p.factory.simulation_manager(s_segfault).run()
        p_segfault = pg_segfault.errored[0].state
        # TODO: fix the permissions segfault to commit if it's a MEM_FETCH
        # this will extend the last simunicorn one more block
        _compare_trace(
            p_segfault.history.descriptions,
            [
                "<Unicorn (STOP_STOPPOINT after 4 steps) from _start+0x0 in uc_stop (0x8048340): 1 sat>",
                "<SimProcedure __libc_start_main from 0x8100004 (__libc_start_main+0x0 in extern-address space (0x4)): 1 sat>",
                "<Unicorn (STOP_STOPPOINT after 14 steps) from __libc_csu_init+0x0 in uc_stop (0x8048650): 1 sat>",
                "<SimProcedure __libc_start_main from 0x820104c (__libc_start_main.after_init+0x0 in extern-address space (0x104c)): 1 sat>",
                "<Unicorn (STOP_SEGFAULT after 7 steps) from main+0x0 in uc_stop (0x80485b5): 1 sat>",
                "<IRSB from stop_segfault+0xb in uc_stop (0x8048508): 1 sat>",
            ],
        )

        s_segfault_angr = p.factory.entry_state(
            args=["a", "a", "a", "a", "a", "a", "a"],
            add_options={so.STRICT_PAGE_ACCESS, so.ENABLE_NX},
        )
        pg_segfault_angr = p.factory.simulation_manager(s_segfault_angr).run()
        p_segfault_angr = pg_segfault_angr.errored[0].state
        assert p_segfault_angr.history.bbl_addrs.hardcopy == p_segfault.history.bbl_addrs.hardcopy
        assert pg_segfault_angr.errored[0].error.addr == pg_segfault.errored[0].error.addr

        # test STOP_SYMBOLIC_BLOCK_EXIT
        s_symbolic_exit = p.factory.entry_state(args=["a"] * 10, add_options=so.unicorn)
        pg_symbolic_exit = p.factory.simulation_manager(s_symbolic_exit).run()
        p_symbolic_exit = pg_symbolic_exit.one_deadended
        _compare_trace(
            p_symbolic_exit.history.descriptions,
            [
                "<Unicorn (STOP_STOPPOINT after 4 steps) from _start+0x0 in uc_stop (0x8048340): 1 sat>",
                "<SimProcedure __libc_start_main from 0x8100004 (__libc_start_main+0x0 in extern-address space (0x4)): 1 sat>",
                "<Unicorn (STOP_STOPPOINT after 14 steps) from __libc_csu_init+0x0 in uc_stop (0x8048650): 1 sat>",
                "<SimProcedure __libc_start_main from 0x820104c (__libc_start_main.after_init+0x0 in extern-address space (0x104c)): 1 sat>",
                "<Unicorn (STOP_SYMBOLIC_BLOCK_EXIT_CONDITION after 7 steps) from main+0x0 in uc_stop (0x80485b5): 1 sat>",
                "<IRSB from stop_symbolic_block_exit+0xe in uc_stop (0x804855d): 2 sat 1 unsat>",
                "<Unicorn (STOP_STOPPOINT after 4 steps) from stop_symbolic_block_exit+0x38 in uc_stop (0x8048587): 1 sat>",
                "<SimProcedure __libc_start_main from 0x8201050 (__libc_start_main.after_main+0x0 in extern-address space (0x1050)): 1 sat>",
            ],
        )

        s_symbolic_exit_angr = p.factory.entry_state(args=["a"] * 10)
        pg_symbolic_exit_angr = p.factory.simulation_manager(s_symbolic_exit_angr).run()
        p_symbolic_exit_angr = pg_symbolic_exit_angr.one_deadended
        assert p_symbolic_exit_angr.history.bbl_addrs.hardcopy == p_symbolic_exit.history.bbl_addrs.hardcopy

    @staticmethod
    def _run_longinit(arch):
        p = angr.Project(os.path.join(test_location, arch, "longinit"), auto_load_libs=False)
        s_unicorn = p.factory.entry_state(add_options=so.unicorn, remove_options={so.SHORT_READS})
        pg = p.factory.simulation_manager(s_unicorn, save_unconstrained=True, save_unsat=True)
        pg.explore()
        s = pg.deadended[0]
        (first, _), (second, _) = s.posix.stdin.content
        s.add_constraints(first == claripy.BVV(b"A" * 9))
        s.add_constraints(second == claripy.BVV(b"B" * 9))
        assert s.posix.dumps(1) == b"You entered AAAAAAAAA and BBBBBBBBB!\n"

    def test_longinit_i386(self):
        self._run_longinit("i386")

    def test_longinit_x86_64(self):
        self._run_longinit("x86_64")

    def test_fauxware_arm(self):
        p = angr.Project(os.path.join(test_location, "armel", "fauxware"), auto_load_libs=False)
        s_unicorn = p.factory.entry_state(add_options=so.unicorn)  # unicorn
        pg = p.factory.simulation_manager(s_unicorn)
        pg.explore()
        assert all("Unicorn" in "".join(p.history.descriptions.hardcopy) for p in pg.deadended)
        assert sorted(pg.mp_deadended.posix.dumps(1).mp_items) == sorted(
            (
                b"Username: \nPassword: \nWelcome to the admin console, trusted user!\n",
                b"Username: \nPassword: \nGo away!",
                b"Username: \nPassword: \nWelcome to the admin console, trusted user!\n",
            )
        )

    def test_fauxware(self):
        p = angr.Project(os.path.join(test_location, "i386", "fauxware"), auto_load_libs=False)
        s_unicorn = p.factory.entry_state(add_options=so.unicorn)  # unicorn
        pg = p.factory.simulation_manager(s_unicorn)
        pg.explore()

        assert all("Unicorn" in "".join(p.history.descriptions.hardcopy) for p in pg.deadended)
        assert sorted(pg.mp_deadended.posix.dumps(1).mp_items) == sorted(
            (
                b"Username: \nPassword: \nWelcome to the admin console, trusted user!\n",
                b"Username: \nPassword: \nGo away!",
                b"Username: \nPassword: \nWelcome to the admin console, trusted user!\n",
            )
        )

    def test_fauxware_aggressive(self):
        p = angr.Project(os.path.join(test_location, "i386", "fauxware"), auto_load_libs=False)
        s_unicorn = p.factory.entry_state(
            add_options=so.unicorn | {so.UNICORN_AGGRESSIVE_CONCRETIZATION},
            remove_options={so.LAZY_SOLVES},
        )  # unicorn
        s_unicorn.unicorn.cooldown_symbolic_stop = 2
        s_unicorn.unicorn.cooldown_unsupported_stop = 2
        s_unicorn.unicorn.cooldown_nonunicorn_blocks = 0

        pg = p.factory.simulation_manager(s_unicorn)
        pg.explore()

        assert len(pg.deadended) == 1

    def test_partial_reads(self):
        """
        This test case if unicorn engine correctly handles case when symbolic taint is introduced by the second partial
        read performed by unicorn. Unicorn triggers memory read hook twice when reading value greater than 8 bytes on
        x86-64.
        """

        p = angr.Project(
            os.path.join(test_location, "x86_64", "test_partial_reads_handling_in_unicorn"),
            auto_load_libs=False,
        )
        # Do not treat as uninitialized memory as symbolic. Prevents introducing undesired symbolic taint
        init_state = p.factory.full_init_state(add_options=so.unicorn | {so.ZERO_FILL_UNCONSTRAINED_MEMORY})
        global_var_val = [
            claripy.BVV(0x41414141, 32),
            claripy.BVV(0x42424242, 32),
            claripy.BVS("symb_val_0", 32),
            claripy.BVS("symb_val_1", 32),
        ]
        global_var_symb = p.loader.find_symbol("global_var")
        # Store every byte separately so that entire variable is not treated as symbolic
        for count, val in enumerate(global_var_val):
            init_state.memory.store(
                global_var_symb.rebased_addr + count * 4, val, endness=init_state.arch.memory_endness
            )

        pg = p.factory.simulation_manager(init_state)
        pg.run()
        assert len(pg.deadended) == 1

    @staticmethod
    def _run_similarity(binpath, depth, prehook=None):
        b = angr.Project(os.path.join(test_location, binpath), auto_load_libs=False)
        cc = b.analyses.CongruencyCheck(throw=True)
        cc.set_state_options(
            left_add_options=so.unicorn,
            left_remove_options={
                so.LAZY_SOLVES,
                so.TRACK_MEMORY_MAPPING,
                so.COMPOSITE_SOLVER,
            },
            right_add_options={so.ZERO_FILL_UNCONSTRAINED_REGISTERS},
            right_remove_options={
                so.LAZY_SOLVES,
                so.TRACK_MEMORY_MAPPING,
                so.COMPOSITE_SOLVER,
            },
        )
        if prehook:
            cc.simgr = prehook(cc.simgr)
        cc.run(depth=depth)

    def test_similarity_fauxware(self):
        def cooldown(pg):
            # gotta skip the initializers because of cpuid and RDTSC
            pg.one_left.unicorn.countdown_nonunicorn_blocks = 39
            return pg

        self._run_similarity(os.path.join("i386", "fauxware"), 1000, prehook=cooldown)

    def test_fp(self):
        with open(os.path.join(bin_location, "tests_src", "manyfloatsum.c"), encoding="utf-8") as fp:
            type_cache = angr.sim_type.parse_defns(fp.read())
        p = angr.Project(os.path.join(test_location, "i386", "manyfloatsum"), auto_load_libs=False)

        for function in (
            "sum_floats",
            "sum_combo",
            "sum_segregated",
            "sum_doubles",
            "sum_combo_doubles",
            "sum_segregated_doubles",
        ):
            args = list(range(len(type_cache[function].args)))
            answer = float(sum(args))
            addr = p.loader.find_symbol(function).rebased_addr
            my_callable = p.factory.callable(addr, prototype=type_cache[function])
            my_callable.set_base_state(p.factory.blank_state(add_options=so.unicorn))
            result = my_callable(*args)
            assert not result.symbolic
            result_concrete = result.args[0]
            assert answer == result_concrete

    def test_unicorn_pickle(self):
        p = angr.Project(os.path.join(test_location, "i386", "fauxware"), auto_load_libs=False)

        def _uni_state():
            # try pickling out paths that went through unicorn
            s_unicorn = p.factory.entry_state(add_options=so.unicorn)
            s_unicorn.unicorn.countdown_nonunicorn_blocks = 0
            s_unicorn.unicorn.countdown_symbolic_stop = 0
            s_unicorn.unicorn.cooldown_nonunicorn_blocks = 0
            s_unicorn.unicorn.cooldown_symbolic_stop = 2
            return s_unicorn

        pg = p.factory.simulation_manager(_uni_state())
        pg.one_active.options.update(so.unicorn)
        pg.run(until=lambda lpg: "Unicorn" in lpg.one_active.history.recent_description)
        assert len(pg.active) > 0

        pgp = pickle.dumps(pg, -1)
        del pg
        gc.collect()
        pg2 = pickle.loads(pgp)
        pg2.explore()

        assert sorted(pg2.mp_deadended.posix.dumps(1).mp_items) == sorted(
            (
                b"Username: \nPassword: \nWelcome to the admin console, trusted user!\n",
                b"Username: \nPassword: \nGo away!",
                b"Username: \nPassword: \nWelcome to the admin console, trusted user!\n",
            )
        )

        # test the pickling of SimUnicorn itself
        p = angr.Project(os.path.join(test_location, "i386", "fauxware"), auto_load_libs=False)
        pg = p.factory.simulation_manager(_uni_state())
        pg.run(n=2)
        assert p.factory.successors(pg.one_active).sort == "Unicorn"

        pgp = pickle.dumps(pg, -1)
        del pg
        gc.collect()
        pg2 = pickle.loads(pgp)
        pg2.explore()

        assert sorted(pg2.mp_deadended.posix.dumps(1).mp_items) == sorted(
            (
                b"Username: \nPassword: \nWelcome to the admin console, trusted user!\n",
                b"Username: \nPassword: \nGo away!",
                b"Username: \nPassword: \nWelcome to the admin console, trusted user!\n",
            )
        )

    def test_concrete_transmits(self):
        p = angr.Project(os.path.join(test_location, "cgc", "PIZZA_00001"), auto_load_libs=False)
        inp = bytes.fromhex("320a310a0100000005000000330a330a340a")

        s_unicorn = p.factory.entry_state(
            add_options=so.unicorn | {so.CGC_NO_SYMBOLIC_RECEIVE_LENGTH},
            stdin=inp,
            flag_page=b"\0" * 4096,
        )
        pg_unicorn = p.factory.simulation_manager(s_unicorn)
        pg_unicorn.run(n=10)

        assert pg_unicorn.one_active.posix.dumps(1) == (
            b"1) Add number to the array\n"
            b"2) Add random number to the array\n"
            b"3) Sum numbers\n"
            b"4) Exit\n"
            b"Randomness added\n"
            b"1) Add number to the array\n"
            b"2) Add random number to the array\n"
            b"3) Sum numbers\n"
            b"4) Exit\n"
            b"  Index: \n"
            b"1) Add number to the array\n"
            b"2) Add random number to the array\n"
            b"3) Sum numbers\n"
            b"4) Exit\n"
        )

    def test_inspect(self):
        p = angr.Project(os.path.join(test_location, "i386", "uc_stop"), auto_load_libs=False)

        def main_state(argc, add_options=None):
            add_options = add_options or so.unicorn
            main_addr = p.loader.find_symbol("main").rebased_addr
            return p.factory.call_state(main_addr, argc, angr.PointerWrapper([]), add_options=add_options)

        # test breaking on specific addresses
        s_break_addr = main_state(1)
        addr0 = 0x08048479  # at the beginning of a basic block, at end of stop_normal function
        addr1 = 0x080485D0  # this is at the beginning of main, in the middle of a basic block
        addr2 = 0x08048461  # another non-bb address, at the start of stop_normal
        addr3 = 0x0804847C  # address of a block that should not get hit (stop_symbolic function)
        addr4 = 0x08048632  # another address that shouldn't get hit, near end of main
        hits = {addr0: 0, addr1: 0, addr2: 0, addr3: 0, addr4: 0}

        def create_addr_action(addr):
            def action(_state):
                hits[addr] += 1

            return action

        for addr in [addr0, addr1, addr2]:
            s_break_addr.inspect.b("instruction", instruction=addr, action=create_addr_action(addr))

        pg_instruction = p.factory.simulation_manager(s_break_addr)
        pg_instruction.run()
        assert hits[addr0] == 1
        assert hits[addr1] == 1
        assert hits[addr2] == 1
        assert hits[addr3] == 0
        assert hits[addr4] == 0

        # test breaking on every instruction
        def collect_trace(options):
            s_break_every = main_state(1, add_options=options)
            trace = []

            def action_every(state):
                trace.append(state.addr)

            s_break_every.inspect.b("instruction", action=action_every)
            pg_break_every = p.factory.simulation_manager(s_break_every)
            pg_break_every.run()

        assert collect_trace(so.unicorn) == collect_trace(set())

    def test_explore(self):
        p = angr.Project(os.path.join(test_location, "i386", "uc_stop"), auto_load_libs=False)

        def main_state(argc, add_options=None):
            add_options = add_options or so.unicorn
            main_addr = p.loader.find_symbol("main").rebased_addr
            return p.factory.call_state(main_addr, argc, angr.PointerWrapper([]), add_options=add_options)

        addr = 0x08048479
        s_explore = main_state(1)
        pg_explore_find = p.factory.simulation_manager(s_explore)
        pg_explore_find.explore(find=addr)
        assert len(pg_explore_find.found) == 1
        assert pg_explore_find.found[0].addr == addr

        pg_explore_avoid = p.factory.simulation_manager(s_explore)
        pg_explore_avoid.explore(avoid=addr)
        assert len(pg_explore_avoid.avoid) == 1
        assert pg_explore_avoid.avoid[0].addr == addr

    def test_single_step(self):
        p = angr.Project(os.path.join(test_location, "i386", "uc_stop"), auto_load_libs=False)

        def main_state(argc, add_options=None):
            add_options = add_options or so.unicorn
            main_addr = p.loader.find_symbol("main").rebased_addr
            return p.factory.call_state(main_addr, argc, angr.PointerWrapper([]), add_options=add_options)

        s_main = main_state(1)

        step1 = s_main.block().instruction_addrs[1]
        successors1 = s_main.step(num_inst=1).successors
        assert len(successors1) == 1
        assert successors1[0].addr == step1

        step5 = s_main.block().instruction_addrs[5]
        successors2 = successors1[0].step(num_inst=4).successors
        assert len(successors2) == 1
        assert successors2[0].addr == step5

    def test_symbolic_flags_preserved_on_stop(self):
        """
        Test if symbolic flags are preserved when unicorn engine stops. This is needed for cases where compare is
        performed in one block and conditional jump in another.
        """

        p = angr.Project(os.path.join(test_location, "x86_64", "test_symbolic_flags_in_unicorn"))
        init_state = p.factory.full_init_state(add_options=angr.options.unicorn)
        simgr = p.factory.simgr(init_state)
        simgr.run()
        result = None
        for final_state in simgr.deadended:
            if b"Congrats" in final_state.posix.dumps(1):
                result = final_state.posix.dumps(0)
                break

        assert result == b"FLAG{l00ps_4r3_t00_34sy_r1gh7??}"

    def test_symbolic_flags_thunk_preserved_on_setup(self):
        """
        Test if the VEX flags thunk is kept whole when unicorn is set up on a state whose flags operand is symbolic and
        whose operation is concrete, as after a compare whose conditional jumps are in later blocks.
        """

        code = """
            push r12
            mov r12d, edi
            call model
            test rax, rax
            je none
            cmp r12d, 2
            je two
            jg big
            test r12d, r12d
            je zero
            mov eax, 1
            pop r12
            ret
        two:
            mov eax, 2
            pop r12
            ret
        big:
            mov eax, 3
            pop r12
            ret
        zero:
            mov eax, 0
            pop r12
            ret
        none:
            mov eax, 9
            pop r12
            ret
        model:
            mov eax, 0x1000
            ret
        """
        p = angr.load_shellcode(code, "amd64", load_address=0x400000)
        x = claripy.BVS("x", 32)
        state = p.factory.call_state(0x400000, x.zero_extend(32), add_options=so.unicorn)
        simgr = p.factory.simulation_manager(state)
        simgr.run()

        expected = {
            -5: 1,
            0: 0,
            1: 1,
            2: 2,
            3: 3,
            100: 3,
        }
        for value, ret in expected.items():
            states = [s for s in simgr.deadended if s.solver.satisfiable(extra_constraints=[x == value])]
            assert [s.solver.eval_one(s.regs.eax, extra_constraints=[x == value]) for s in states] == [ret]

    def test_setup_flags_keeps_symbolic_flags(self):
        """
        Test if setting up unicorn's flags register keeps the flags of a VEX flags thunk whose operand is symbolic.
        """

        for arch in ("AMD64", "ARMEL"):
            state = minimal_project(arch).factory.blank_state(add_options=so.unicorn)
            state.regs.cc_op = 2
            state.regs.cc_dep1 = claripy.BVS("x", state.arch.bits)
            state.regs.cc_dep2 = 2
            state.regs.cc_ndep = 0
            before = state.copy()
            state.unicorn.setup_flags()
            assert not state.solver.satisfiable(extra_constraints=[state.regs.flags != before.regs.flags])

    @staticmethod
    def _run_shellcode(code, arch, thumb, use_unicorn, setup=None, max_steps=None):
        """
        Run code that ends with a nop instruction until that instruction is reached, with or without the unicorn
        engine. The code is placed away from the start of its page. Returns the final states, ordered by the
        blocks they executed.
        """

        # Note: use hexadecimal notation for immediate values greater than 9 in code. keystone sometimes parses numbers
        # without a prefix as hexadecimal ones after assembling code for a different architecture.
        load_address = 0x10000
        padding = 0x40
        p = angr.load_shellcode("nop\n" * padding + code, arch, load_address=load_address, thumb=thumb)
        nop_size = len(p.arch.asm("nop", load_address, thumb=thumb))
        start = load_address + padding * nop_size
        end = p.loader.main_object.max_addr + 1 - nop_size
        if thumb:
            start |= 1
            end |= 1
        p.hook(end, angr.SIM_PROCEDURES["stubs"]["PathTerminator"]())

        opts = {so.ZERO_FILL_UNCONSTRAINED_MEMORY, so.ZERO_FILL_UNCONSTRAINED_REGISTERS}
        if use_unicorn:
            opts |= so.unicorn
        state = p.factory.blank_state(addr=start, add_options=opts)
        # Create the stack page: unicorn stops if it has to create pages
        state.memory.store(state.regs.sp - 0x800, b"\0" * 0x1000)
        if setup is not None:
            setup(state)
        if use_unicorn:
            # Use unicorn whenever possible
            state.unicorn.cooldown_nonunicorn_blocks = 0
            state.unicorn.cooldown_symbolic_stop = 0
            state.unicorn.cooldown_unsupported_stop = 0
            state.unicorn.cooldown_stop_point = 0
            if max_steps is not None:
                state.unicorn.max_steps = max_steps

        simgr = p.factory.simgr(state)
        simgr.run(until=lambda sm: sm.move("active", "done", lambda s: s.addr == end) and False, n=100)
        assert not simgr.active
        assert not simgr.errored
        return sorted(simgr.done, key=lambda s: list(s.history.bbl_addrs))

    def _check_unicorn_matches_vex(self, code, arch="armel", thumb=True, setup=None, memory=(), max_steps=None):
        """
        Run code in VEX engine and unicorn engine and check that the registers, memory and history of the final states
        are the same. Returns the final states of the unicorn engine run.
        """

        vex_states = self._run_shellcode(code, arch, thumb, False, setup=setup)
        uc_states = self._run_shellcode(code, arch, thumb, True, setup=setup, max_steps=max_steps)
        assert len(vex_states) == len(uc_states)
        for vex_state, uc_state in zip(vex_states, uc_states):
            assert any(desc.startswith("<Unicorn") for desc in uc_state.history.descriptions)
            assert list(uc_state.history.bbl_addrs) == list(vex_state.history.bbl_addrs)
            values = [(name, getattr(vex_state.regs, name), getattr(uc_state.regs, name)) for name in _arch_regs(arch)]
            values += [(hex(addr), vex_state.memory.load(addr, 4), uc_state.memory.load(addr, 4)) for addr in memory]
            solver = claripy.Solver()
            for name, vex_value, uc_value in values:
                assert vex_value.symbolic == uc_value.symbolic, name
                assert not solver.satisfiable(extra_constraints=[vex_value != uc_value]), name
            assert not solver.satisfiable(
                extra_constraints=[
                    claripy.And(*vex_state.solver.constraints) != claripy.And(*uc_state.solver.constraints)
                ]
            )

        return uc_states

    def test_thumb_concrete(self):
        """
        Test if THUMB code runs in unicorn and if the state is still in THUMB mode with correct flags after every stop.
        """

        code = """
            movs r0, #5
            movs r1, #0
        loop:
            adds r1, r1, r0
            subs r0, #1
            bne loop
            bl func
            cmp r1, #0x16
            b check
        check:
            ite eq
            moveq r2, #1
            movne r2, #2
            adcs r3, r3
            b end
        func:
            push {r4, lr}
            movs r4, #7
            adds r1, r1, r4
            pop {r4, pc}
        end:
            nop
        """
        for max_steps in (None, 1, 2):
            (state,) = self._check_unicorn_matches_vex(code, max_steps=max_steps)
            assert all(addr & 1 for addr in state.history.bbl_addrs)
            assert state.solver.eval_one(state.regs.r1) == 22
            assert state.solver.eval_one(state.regs.r2) == 1
            assert state.solver.eval_one(state.regs.r3) == 1

    def test_arm_flags_synced_on_stop(self):
        """
        Test if the condition flags computed in unicorn are used by a conditional jump executed after unicorn stops.
        """

        code = """
            mov r0, #5
            cmp r0, #7
            b check
        check:
            blt less
            mov r1, #1
            b end
        less:
            mov r1, #2
            b end
        end:
            nop
        """
        (state,) = self._check_unicorn_matches_vex(code, thumb=False, max_steps=1)
        assert state.solver.eval_one(state.regs.r1) == 2

    def test_arm_thumb_interworking(self):
        """
        Test if switches between ARM and THUMB modes are tracked, both inside unicorn and across stops.
        """

        code = """
            movs r0, #5
            adr r1, armcode
            bx r1
            .align 2
        armcode:
            .arm
            add r0, r0, #1
            add r3, r2, r0
            add r4, pc, #5
            bx r4
            .thumb
            adds r0, #1
            adds r3, r3, r0
            b end
        end:
            nop
        """

        def setup(state):
            state.regs.r2 = claripy.BVS("x", 32, explicit_name=True)

        for max_steps in (None, 1):
            (state,) = self._check_unicorn_matches_vex(code, setup=setup, max_steps=max_steps)
            assert [addr & 1 for addr in state.history.bbl_addrs] == [1, 0, 1]

    def test_thumb_symbolic(self):
        """
        Test if symbolic data is handled correctly when executing THUMB code in unicorn: the statements to re-execute
        in VEX should be those of the block lifted in native interface.
        """

        def setup(state):
            state.regs.r2 = claripy.BVS("x", 32, explicit_name=True)
            state.regs.r8 = claripy.BVS("y", 32, explicit_name=True)
            state.memory.store(0x20000, claripy.BVS("m", 32, explicit_name=True), endness="Iend_LE")
            state.memory.store(0x20004, b"\x11\x22\x33\x44" * 4)

        symbolic_memory = """
            movs r0, #2
            lsls r0, r0, #0x10
            ldr r1, [r0]
            ldr r3, [r0, #4]
            b n1
        n1:
            adds r4, r1, r3
            str r4, [r0, #8]
            ldr.w r5, [r0, #8]
            movs r6, #9
            b n2
        n2:
            add.w r5, r5, r6
            str r5, [r0, #0xc]
            ldrb r7, [r0, #1]
            strh r7, [r0, #0x10]
            b end
        end:
            nop
        """
        (state,) = self._check_unicorn_matches_vex(symbolic_memory, setup=setup, memory=(0x20008, 0x2000C, 0x20010))
        assert state.regs.r5.symbolic
        # All blocks should have been executed in unicorn
        assert not any(desc.startswith("<IRSB") for desc in state.history.descriptions)

        symbolic_it_block = """
            movs r0, #5
            b n0
        n0:
            cmp r2, #5
            ite eq
            moveq r1, #1
            movne r1, #2
            adds r3, r1, r0
            b n1
        n1:
            cmp r3, #6
            itte ne
            addne r4, r3, #1
            lslne r4, r4, #1
            moveq r4, r8
            b n2
        n2:
            movs r5, #0
            adcs r5, r5
            b end
        end:
            nop
        """
        (state,) = self._check_unicorn_matches_vex(symbolic_it_block, setup=setup)
        assert state.regs.r1.symbolic
        assert state.regs.r4.symbolic
        assert state.regs.r5.symbolic

        symbolic_branch = """
            movs r0, #5
            movs r4, #0
            b n0
        n0:
            cmp r2, #3
            b n1
        n1:
            bhi hi
            adds r4, #1
            b n2
        hi:
            adds r4, #2
        n2:
            lsrs r3, r2, #4
            cbz r3, z
            adds r4, #4
        z:
            adds r4, r4, r2
            b end
        end:
            nop
        """
        states = self._check_unicorn_matches_vex(symbolic_branch, setup=setup)
        assert len(states) == 3

    def test_symbolic_condition_of_select(self):
        """
        Test if a value selected using a symbolic condition is symbolic even if the values to select from are concrete.
        """

        code = """
            mov rax, 1
            mov rbx, 2
            cmp rdi, 5
            jmp n0
        n0:
            cmove rax, rbx
            add rax, 3
            jmp end
        end:
            nop
        """

        def setup(state):
            state.regs.rdi = claripy.BVS("x", 64, explicit_name=True)

        (state,) = self._check_unicorn_matches_vex(code, arch="amd64", thumb=False, setup=setup)
        assert state.regs.rax.symbolic
        assert state.solver.eval_one(state.regs.rax, extra_constraints=[state.regs.rdi == 5]) == 5
        assert state.solver.eval_one(state.regs.rax, extra_constraints=[state.regs.rdi == 6]) == 4

    def test_vex_archinfo_ctypes_mirror_matches_native(self):
        """
        The ctypes mirror of VexArchInfo is passed by value into unicornlib, which lifts with it. If it
        drifts from libvex.h, fields land at the wrong offsets and blocks are lifted with the wrong
        settings (e.g. a zeroed x86_cr0 makes the x86 front end decode 16-bit real-mode code).
        """

        if _UC_NATIVE is None:
            raise unittest.SkipTest("native unicorn support is unavailable")

        _check_vex_archinfo_layout(_UC_NATIVE)


if __name__ == "__main__":
    import logging

    logging.getLogger("angr.state_plugins.unicorn_engine").setLevel("DEBUG")
    logging.getLogger("angr.engines.unicorn_engine").setLevel("INFO")
    logging.getLogger("angr.factory").setLevel("DEBUG")
    logging.getLogger("angr.project").setLevel("DEBUG")

    unittest.main()
