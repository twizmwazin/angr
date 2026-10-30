from __future__ import annotations

import gc
import unittest

from angr import claripy


class KeyedAnnotation(claripy.Annotation):
    """A user-defined annotation whose identity is content-based via a custom
    __hash__/__eq__: only ``key`` matters. ``extra`` varies fields the pickled
    bytes include without changing identity."""

    def __init__(self, key, extra=None):
        self.key = key
        self.extra = extra

    def __hash__(self):
        return hash(("KeyedAnnotation", self.key))

    def __eq__(self, other):
        return isinstance(other, KeyedAnnotation) and other.key == self.key


class UnpickleCountingAnnotation(claripy.Annotation):
    """A user-defined annotation that counts how often it is unpickled. It is
    not eliminatable, so it survives into the solver's constraints."""

    eliminatable = False
    relocatable = True
    unpickled = 0

    def __init__(self, key):
        self.key = key

    def __hash__(self):
        return hash(("UnpickleCountingAnnotation", self.key))

    def __eq__(self, other):
        return isinstance(other, UnpickleCountingAnnotation) and other.key == self.key

    def __setstate__(self, state):
        type(self).unpickled += 1
        self.__dict__.update(state)


class TestUnknownAnnotationIdentity(unittest.TestCase):
    """Unknown (Python-defined) annotations are identified by the Python
    object's hash, mirroring claripy's use of annotation __hash__/__eq__ — not
    by their (non-canonical) pickled bytes."""

    def setUp(self):
        self.base = claripy.BVS("v", 32, explicit_name=True)

    def test_custom_hash_content_equal_are_identical(self):
        a = self.base.annotate(KeyedAnnotation("a"))
        b = self.base.annotate(KeyedAnnotation("a"))
        self.assertEqual(a.hash(), b.hash())

    def test_custom_hash_distinct_keys_differ(self):
        a = self.base.annotate(KeyedAnnotation("a"))
        b = self.base.annotate(KeyedAnnotation("b"))
        self.assertNotEqual(a.hash(), b.hash())

    def test_custom_hash_ignores_fields_outside_identity(self):
        # Two annotations equal by __eq__/__hash__ but pickling to different
        # bytes (extra differs) still hash equal: identity follows the object's
        # hash, not the pickled bytes.
        a = self.base.annotate(KeyedAnnotation("a", extra=1))
        b = self.base.annotate(KeyedAnnotation("a", extra=2))
        self.assertEqual(a.hash(), b.hash())

    def test_same_object_is_stable(self):
        anno = KeyedAnnotation("a")
        self.assertEqual(self.base.annotate(anno).hash(), self.base.annotate(anno).hash())

    def test_read_back_without_unpickling(self):
        # Once no Python wrapper references the annotation any more, reading it
        # back out of an AST hands back the attached object instead of
        # unpickling a copy.
        solver = claripy.Solver()
        solver.add((claripy.BVS("w", 32) == 1).annotate(UnpickleCountingAnnotation("w")))
        gc.collect()
        before = UnpickleCountingAnnotation.unpickled
        (constraint,) = solver.constraints
        self.assertIn(UnpickleCountingAnnotation("w"), constraint.annotations)
        self.assertEqual(UnpickleCountingAnnotation.unpickled, before)
