#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os.path
import unittest

import angr
from tests.common import WORKER, bin_location

test_location = os.path.join(bin_location, "tests")


class TestMemloadResolver(unittest.TestCase):
    def test_indirect_jump_should_start_new_functions(self):
        bin_path = os.path.join(test_location, "x86_64", "fmt-rust-stripped")
        proj = angr.Project(bin_path, auto_load_libs=False)
        # Scan only the neighbourhoods of the seven functions the assertions look at: a whole-binary CFG of this
        # Rust binary takes minutes, while the thunk->function and stub->function splits are decided by the jump
        # sites (0x4965c0 `jmp *[got]`, 0x495fe0 `jmp/call 0x496030`, 0x496c30 `call *[got]`) and their targets.
        # Do NOT seed the targets as function_starts: that would make the assertions trivially true.
        cfg = proj.analyses.CFG(
            normalize=True,
            show_progressbar=not WORKER,
            start_at_entry=False,
            regions=[
                (0x495F00, 0x497000),  # crt-area drop glue, thunk 0x4965c0, caller 0x496920
                (0x498700, 0x498A00),  # callee of 0x495fe7, and 0x498930 (target of stub 0x496030)
                (0x49C400, 0x49CD00),  # 0x49c4d0..0x49cc36
                (0x4FB000, 0x4FB100),  # callee of `call *%r14` at 0x49c507 (decides fall-through to 0x49c50a)
                (0x566A00, 0x566C00),  # 0x566a50..0x566bee, target of the ten `jmp *0x184160(%rip)` thunks
            ],
        )
        # function 0x566a50 should be a separate function
        node = cfg.model.get_any_node(0x566A50)
        assert node is not None
        assert node.function_address == 0x566A50
        # function 0x498930 should be a separate function
        node = cfg.model.get_any_node(0x496030)
        assert node is not None
        assert node.function_address == 0x496030
        # function 0x49C4D0 should include many blocks, including 0x49C50A
        func = cfg.kb.functions[0x49C4D0]
        assert func is not None
        assert 0x49C50A in func.block_addrs_set
        assert not cfg.kb.functions.contains_addr(0x49C50A)


if __name__ == "__main__":
    unittest.main()
