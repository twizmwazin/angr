#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

__package__ = __package__ or "tests.engines"  # pylint:disable=redefined-builtin

import gc
import os
import pickle
import re
import unittest
from io import BytesIO

import archinfo
import claripy
import cle

import angr
from angr import options as so
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


def _remove_addr_from_trace_item(trace_item_str):
    m = re.match(r"(<\S+ \S+) from .*(:[\s\S]+)", trace_item_str)
    if m is None:
        return None
    return m.group(1) + m.group(2)


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


class TestUnicornThumb(unittest.TestCase):
    """
    Tests for ARM code that runs in, or switches to, THUMB mode. angr encodes the execution mode in the least
    significant bit of an address, unicorn in the CPSR T bit.
    """

    ARM_BASE = 0x1000
    THUMB_BASE = 0x2000

    @staticmethod
    def _project(arm_code=b"", thumb_code=b""):
        arch = archinfo.ArchARMEL()
        segments = []
        if arm_code:
            segments.append((0, TestUnicornThumb.ARM_BASE, len(arm_code)))
        if thumb_code:
            segments.append((len(arm_code), TestUnicornThumb.THUMB_BASE, len(thumb_code)))

        blob = cle.Blob(
            None,
            BytesIO(arm_code + thumb_code),
            arch=arch,
            segments=segments,
            base_addr=0,
            entry_point=TestUnicornThumb.ARM_BASE if arm_code else TestUnicornThumb.THUMB_BASE | 1,
        )
        return angr.Project(blob)

    @staticmethod
    def _trace(project, entry, blocks, unicorn, registers=("r0", "r1", "r2", "r3", "r4")):
        """
        Execute `blocks` basic blocks one at a time. unicorn is limited to a single block per step so that its trace
        can be compared against the one produced by VEX.
        """
        add_options = {so.ZERO_FILL_UNCONSTRAINED_MEMORY, so.ZERO_FILL_UNCONSTRAINED_REGISTERS}
        if unicorn:
            add_options |= so.unicorn

        state = project.factory.blank_state(addr=entry, add_options=add_options)
        state.regs.sp = 0x7FFF0000
        simgr = project.factory.simulation_manager(state)
        trace = []
        for _ in range(blocks):
            if unicorn:
                for active in simgr.active:
                    active.unicorn.max_steps = 1

            simgr.step()
            assert len(simgr.active) == 1, f"expected a single successor, got {simgr.active}"
            state = simgr.active[0]
            if unicorn:
                assert "Unicorn" in state.history.recent_description
            trace.append(
                (
                    state.addr,
                    tuple(state.solver.eval(getattr(state.regs, reg)) for reg in registers),
                    tuple(state.history.recent_bbl_addrs),
                )
            )

        return trace

    def test_thumb(self):
        """THUMB code executed across multiple unicorn runs stays in THUMB mode."""
        arch = archinfo.ArchARMEL()
        thumb_code = arch.asm(
            "movs r0, #1; b second; second: movs r1, #2; b third; third: adds r2, r0, r1; b .",
            addr=self.THUMB_BASE,
            thumb=True,
            as_bytes=True,
        )
        project = self._project(thumb_code=thumb_code)

        unicorn_trace = self._trace(project, self.THUMB_BASE | 1, 4, unicorn=True)
        assert unicorn_trace == self._trace(project, self.THUMB_BASE | 1, 4, unicorn=False)
        assert all(addr & 1 for addr, _, _ in unicorn_trace)
        assert all(bbl_addr & 1 for _, _, bbl_addrs in unicorn_trace for bbl_addr in bbl_addrs)
        assert unicorn_trace[-1][1][2] == 3

    def test_arm_to_thumb(self):
        """Switching from ARM to THUMB mode and back while executing in unicorn."""
        arch = archinfo.ArchARMEL()
        arm_prologue = arch.asm(
            f"mov r0, #1; mov r1, #2; movw r3, #{self.THUMB_BASE | 1:#x}; bx r3",
            addr=self.ARM_BASE,
            as_bytes=True,
        )
        arm_epilogue_addr = self.ARM_BASE + len(arm_prologue)
        thumb_code = arch.asm(
            f"adds r2, r0, r1; movw r3, #{arm_epilogue_addr:#x}; bx r3",
            addr=self.THUMB_BASE,
            thumb=True,
            as_bytes=True,
        )
        arm_epilogue = arch.asm("adds r4, r2, #1; b .", addr=arm_epilogue_addr, as_bytes=True)
        project = self._project(arm_code=arm_prologue + arm_epilogue, thumb_code=thumb_code)

        unicorn_trace = self._trace(project, self.ARM_BASE, 4, unicorn=True)
        assert unicorn_trace == self._trace(project, self.ARM_BASE, 4, unicorn=False)
        assert [addr for addr, _, _ in unicorn_trace][:2] == [self.THUMB_BASE | 1, arm_epilogue_addr]
        assert unicorn_trace[-1][1][2] == 3
        assert unicorn_trace[-1][1][4] == 4

    def test_thumb_to_arm(self):
        """Switching from THUMB to ARM mode and back while executing in unicorn."""
        arch = archinfo.ArchARMEL()
        thumb_prologue = arch.asm(
            f"movs r0, #1; movs r1, #2; movw r3, #{self.ARM_BASE:#x}; bx r3",
            addr=self.THUMB_BASE,
            thumb=True,
            as_bytes=True,
        )
        thumb_epilogue_addr = self.THUMB_BASE + len(thumb_prologue)
        arm_code = arch.asm(
            f"add r2, r0, r1; movw r3, #{thumb_epilogue_addr | 1:#x}; bx r3",
            addr=self.ARM_BASE,
            as_bytes=True,
        )
        thumb_epilogue = arch.asm("adds r4, r2, #1; b .", addr=thumb_epilogue_addr, thumb=True, as_bytes=True)
        project = self._project(arm_code=arm_code, thumb_code=thumb_prologue + thumb_epilogue)

        unicorn_trace = self._trace(project, self.THUMB_BASE | 1, 4, unicorn=True)
        assert unicorn_trace == self._trace(project, self.THUMB_BASE | 1, 4, unicorn=False)
        assert [addr for addr, _, _ in unicorn_trace][:2] == [self.ARM_BASE, thumb_epilogue_addr | 1]
        assert unicorn_trace[-1][1][2] == 3
        assert unicorn_trace[-1][1][4] == 4

    def test_thumb_hook(self):
        """Unicorn stops at a hook on a THUMB function and hands the state over with the THUMB bit set."""
        arch = archinfo.ArchARMEL()
        thumb_code = arch.asm(
            "movs r0, #1; bl target; movs r2, #5; b .; target: movs r1, #0x11; bx lr",
            addr=self.THUMB_BASE,
            thumb=True,
            as_bytes=True,
        )
        assert len(thumb_code) == 14
        target = self.THUMB_BASE + 10
        project = self._project(thumb_code=thumb_code)

        results = []
        for unicorn in (False, True):
            hits = []

            def hook(state, hits=hits):
                hits.append(state.addr)
                state.regs.r1 = 0x99
                state.regs.pc = state.regs.lr

            project.unhook(target | 1)
            project.hook(target | 1, hook, length=0)

            add_options = {so.ZERO_FILL_UNCONSTRAINED_MEMORY, so.ZERO_FILL_UNCONSTRAINED_REGISTERS}
            if unicorn:
                add_options |= so.unicorn

            state = project.factory.blank_state(addr=self.THUMB_BASE | 1, add_options=add_options)
            state.regs.sp = 0x7FFF0000
            simgr = project.factory.simulation_manager(state)
            for _ in range(4):
                simgr.step()

            assert not simgr.errored
            assert len(simgr.active) == 1
            succ = simgr.active[0]
            results.append((hits, succ.addr, succ.solver.eval(succ.regs.r1), succ.solver.eval(succ.regs.r2)))

        assert results[0][0] == [target | 1]
        assert results[0][2] == 0x99
        assert results[0][3] == 5
        assert results[1] == results[0]

    def test_fauxware_thumb(self):
        """A THUMB binary executed in unicorn, stopping often enough that unicorn returns in THUMB mode."""
        project = angr.Project(os.path.join(test_location, "armhf", "fauxware"), auto_load_libs=False)
        assert project.arch.is_thumb(project.entry)

        state = project.factory.entry_state(add_options=so.unicorn)
        state.unicorn.max_steps = 2
        simgr = project.factory.simulation_manager(state)
        simgr.run()

        assert not simgr.errored
        assert all("Unicorn" in "".join(s.history.descriptions.hardcopy) for s in simgr.deadended)
        assert sorted(simgr.mp_deadended.posix.dumps(1).mp_items) == sorted(
            (
                b"Username: \nPassword: \nWelcome to the admin console, trusted user!\n",
                b"Username: \nPassword: \nGo away!",
                b"Username: \nPassword: \nWelcome to the admin console, trusted user!\n",
            )
        )


if __name__ == "__main__":
    import logging

    logging.getLogger("angr.state_plugins.unicorn_engine").setLevel("DEBUG")
    logging.getLogger("angr.engines.unicorn_engine").setLevel("INFO")
    logging.getLogger("angr.factory").setLevel("DEBUG")
    logging.getLogger("angr.project").setLevel("DEBUG")

    unittest.main()
