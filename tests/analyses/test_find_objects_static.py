#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestFindObjectsStatic(unittest.TestCase):
    def test_object_identification_x86_64(self):
        self._test_object_identification_x86_64(with_calling_conventions=False)

    def test_object_identification_x86_64_with_calling_conventions(self):
        self._test_object_identification_x86_64(with_calling_conventions=True)

    def _test_object_identification_x86_64(self, with_calling_conventions: bool):
        p = angr.Project(os.path.join(test_location, "x86_64", "cpp_classes"), auto_load_libs=False)
        if with_calling_conventions:
            p.analyses.CFGFast(cross_references=True)
            for func in p.kb.functions.values():
                func.calling_convention = angr.calling_conventions.SimCCSystemVAMD64(p.arch)
        object_identifier_analysis = p.analyses.StaticObjectFinder()
        possible_objects_dict = object_identifier_analysis.possible_objects
        possible_constructors = object_identifier_analysis.possible_constructors
        class_labels = []

        for possible_object in possible_objects_dict.values():
            class_labels.append(possible_object.class_name)

        assert "C" in class_labels
        assert len(possible_objects_dict) == 2
        assert len(possible_constructors) == 1
        assert 0x401512 in possible_constructors
        assert len(possible_constructors[0x401512]) == 2


if __name__ == "__main__":
    unittest.main()
