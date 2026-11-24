#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import unittest

import angr
from tests.common import bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


class TestStackFrameCollapse(unittest.TestCase):
    """
    At O0 every local lives in the stack frame and rbp holds sp-8. A frame-pointer-relative access that survives
    expression folding as ``rbp - N`` used to be read by ssailification as an array spanning from the frame
    pointer, which merged every local of the function into one slot.
    """

    @staticmethod
    def _decompile(binary: str, func_name: str):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", binary)
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        func = proj.kb.functions.function(name=func_name)
        assert func is not None
        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        return dec

    # The check on bzip2's BZ2_decompress (its locals stay separate stack variables) is piggybacked on
    # test_phoenix_goto_successors.py::test_bzip2_o0_decompress_structures_completely, which already decompiles that
    # function; one decompilation of it takes over half a minute.

    def test_gzip_o0_fprint_off_reference_offset(self):
        # p = buf + sizeof buf: the reference must point past the end of the buffer, not before its start
        dec = self._decompile("decbench_gzip_O0", "fprint_off")
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        text = dec.codegen.text

        assert re.search(r"= &v\d+ \+ \d+;", text) is not None
        assert re.search(r"&v\d+ - \d+", text) is None


if __name__ == "__main__":
    unittest.main()
