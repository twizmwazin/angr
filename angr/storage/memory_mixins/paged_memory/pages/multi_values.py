from __future__ import annotations

from collections.abc import Iterable, Iterator

import archinfo

from angr import claripy
from angr.storage.memory_object import bv_slice

_TOPS: dict[int, claripy.ast.BV] = {}


class MultiValues:
    """
    Represents a byte vector where each byte can have one or multiple values.

    As an implementation optimization (so that we do not create excessive sets and dicts), self._single_value stores a
    claripy AST when this MultiValues object represents only one value at offset 0.
    """

    __slots__ = (
        "_single_value",
        "_values",
    )

    _single_value: claripy.ast.BV | None
    _values: dict[int, set[claripy.ast.BV]] | None

    def __init__(self, v: claripy.ast.BV | MultiValues | dict[int, set[claripy.ast.BV]] | None = None):
        if v is None:
            self._single_value = None
            self._values = {}
        elif isinstance(v, claripy.ast.BV):
            self._single_value = v
            self._values = None
        elif isinstance(v, MultiValues):
            # copy-construction: the new object must own its offset map, otherwise mutating either object
            # (e.g. add_value()) silently mutates the other, and mutating one while iterating the other raises
            self._single_value = v._single_value
            self._values = None if v._values is None else {offset: set(values) for offset, values in v._values.items()}
        elif isinstance(v, dict):
            self._single_value = None
            self._values = v
        else:
            raise TypeError(type(v))

        # if only one value is passed in, assign it to self._single_value
        if self._values and len(self._values) == 1 and 0 in self._values and len(self._values[0]) == 1:
            self._single_value = next(iter(self._values[0]))
            self._values = None

        if self._values:
            # sanity check
            for vs in self._values.values():
                if not isinstance(vs, set):
                    raise TypeError("Each value in the offset-to-values dict must be a set!")
                for value in vs:
                    if not isinstance(value, claripy.ast.BV):
                        raise TypeError(f"MultiValues only holds bitvectors, got {type(value)}")

    def add_value(self, offset: int, value: claripy.ast.BV) -> None:
        if not isinstance(value, claripy.ast.BV):
            raise TypeError(f"MultiValues only holds bitvectors, got {type(value)}")
        if len(value) == 0:
            return
        if self._single_value is not None:
            if len(self._single_value) == 0:
                if offset == 0:
                    self._single_value = value
                else:
                    self._single_value = None
                    self._values = {offset: {value}}
                return
            self._values = {0: {self._single_value}}
            self._single_value = None

        if self._values is None:
            self._values = {}

        if offset not in self._values:
            self._values[offset] = set()

        # if value overlaps with existing values, we need to break them down

        succ_offset = self._adjacent_offset(offset, before=False)
        if succ_offset is not None:
            value_end = offset + value.size() // 8
            if value_end > succ_offset:
                # value is too long. we need to break value into two
                mid_value_size = succ_offset - offset
                remaining_value = value[value.size() - mid_value_size * 8 - 1 : 0]
                # update value
                value = value[value.size() - 1 : value.size() - mid_value_size * 8]
                self.add_value(succ_offset, remaining_value)

        if self._values[offset]:
            curr_value_size = next(iter(self._values[offset])).size() // 8
            if curr_value_size > value.size() // 8:
                # we need to break existing values
                new_curr_values = set()
                remaining_values = set()
                for v in self._values[offset]:
                    new_curr_values.add(v[v.size() - 1 : v.size() - value.size()])
                    remaining_values.add(v[v.size() - value.size() - 1 : 0])
                self._values[offset] = new_curr_values
                for v in remaining_values:
                    self.add_value(offset + value.size() // 8, v)
            elif curr_value_size < value.size() // 8:
                # value is too long. we need to break value into two
                remaining_value = value[value.size() - curr_value_size * 8 - 1 : 0]
                # update value
                value = value[value.size() - 1 : value.size() - curr_value_size * 8]
                self.add_value(offset + curr_value_size, remaining_value)

        self._values[offset].add(value)

        pre_offset = self._adjacent_offset(offset, before=True)
        if pre_offset is not None:
            pre_values = self._values[pre_offset]
            pre_values_size = next(iter(pre_values)).size() // 8
            if pre_offset + pre_values_size > offset:
                # we need to break the preceding values
                new_pre_value_size = offset - pre_offset
                new_pre_values = set()
                remaining_values = set()
                for v in pre_values:
                    new_pre_values.add(v[v.size() - 1 : v.size() - new_pre_value_size * 8])
                    remaining_values.add(v[v.size() - new_pre_value_size * 8 - 1 : 0])
                self._values[pre_offset] = new_pre_values
                for v in remaining_values:
                    self.add_value(offset, v)

    def one_value(self, strip_annotations: bool = False) -> claripy.ast.BV | None:
        if self._single_value is not None:
            return self._single_value

        assert self._values is not None

        if len(self._values) == 1 and 0 in self._values and len(self._values[0]) == 1:
            return next(iter(self._values[0]))
        if strip_annotations:
            all_values_wo_annotations = {
                bv.remove_annotations(bv.annotations) if bv.annotations else bv for bv in self._values[0]
            }
            if len(all_values_wo_annotations) == 1:
                return next(iter(all_values_wo_annotations))
        return None

    def __len__(self) -> int:
        if self._single_value is not None:
            return self._single_value.size()

        assert self._values is not None

        if len(self._values) == 0:
            return 0

        max_offset = max(self._values.keys())
        max_len = max(x.size() for x in self._values[max_offset])
        return max_offset * 8 + max_len  # FIXME: we are assuming byte_width of 8

    def merge(self, mv: MultiValues) -> MultiValues:
        new_values = {k: set(v) for k, v in self.items()}
        for off, vs in mv.items():
            if off not in new_values:
                new_values[off] = set(vs)
            else:
                new_values[off] |= vs
        return MultiValues(new_values)

    @staticmethod
    def top(bits: int) -> claripy.ast.BV:
        """
        Get the TOP value of the given width. TOP represents an unknown value.

        :param bits:    Width of the TOP value (in bits).
        :return:        The TOP value.
        """
        r = _TOPS.get(bits)
        if r is None:
            r = _TOPS[bits] = claripy.BVS("TOP", bits, explicit_name=True)
        return r

    @staticmethod
    def is_top(v: claripy.ast.Base) -> bool:
        """
        Check if the given value is TOP itself.
        """
        return isinstance(v, claripy.ast.BV) and v.op == "BVS" and v.args[0] == "TOP"

    @staticmethod
    def contains_top(v: claripy.ast.Base) -> bool:
        """
        Check if the given value is TOP or is an expression over TOP.
        """
        return isinstance(v, claripy.ast.Base) and "TOP" in v.variables

    def limit(
        self,
        element_limit: int,
        merge_into_top: bool = True,
        annotation_limit: int = 256,
    ) -> MultiValues:
        """
        Collapse the values at every offset that holds more than `element_limit` values. See collapse_values().

        :return:    self if no offset exceeds the limit, otherwise a new MultiValues object.
        """
        offset_to_values: dict[int, set[claripy.ast.BV]] = {}
        collapsed = False
        for offset, values in self.items():
            if len(values) > element_limit:
                bits = max(len(v) for v in values)
                values = self.collapse_values(
                    values,
                    bits,
                    element_limit,
                    merge_into_top=merge_into_top,
                    annotation_limit=annotation_limit,
                )
                collapsed = True
            offset_to_values[offset] = set(values)
        if not collapsed:
            return self
        return MultiValues(offset_to_values)

    @staticmethod
    def collapse_values(
        values: Iterable[claripy.ast.BV],
        bits: int,
        element_limit: int,
        merge_into_top: bool = True,
        annotation_limit: int = 256,
    ) -> set[claripy.ast.BV]:
        """
        Collapse a set of values into a single (possibly TOP) value when it contains TOP or exceeds the element limit.
        Annotations of all values are migrated onto the result.

        :param values:              The values to collapse.
        :param bits:                Width of the TOP value to create, in bits.
        :param element_limit:       The maximum number of values to keep without collapsing.
        :param merge_into_top:      If True, any value that contains TOP forces the set to collapse into TOP;
                                    otherwise, such values are treated like any other value.
        :param annotation_limit:    The maximum number of annotations to migrate onto the collapsed value.
        :return:                    The values, either unchanged or collapsed into a single value.
        """
        values_set = set(values)
        has_top = merge_into_top and any(MultiValues.contains_top(v) for v in values_set)
        if not has_top and len(values_set) <= element_limit:
            return values_set

        if has_top:
            ret_val = MultiValues.top(bits)
        else:
            # strip annotations from each value and see how many raw values there are in total
            # We have to use hash manually to determine uniqueness here, because if __hash__ collides,
            # python implicitly calls __eq__ to determine if the two objects are actually the same
            # and that just results in a new AST for a BV. Python then tries to convert that AST to a bool
            # which fails with the safeguard in claripy.ast.bool.Bool.__bool__.
            stripped_values_dict = {v.hash(): v for v in values_set}
            # if there is only one raw value, get the AST back from the hash dict
            ret_val = (
                MultiValues.top(bits) if len(stripped_values_dict) > 1 else next(iter(stripped_values_dict.values()))
            )

        # migrate annotations
        annotations = []
        annotations_set = set()
        for v in values_set:
            for anno in v.annotations:
                if anno not in annotations_set:
                    annotations.append(anno)
                    annotations_set.add(anno)
        if annotations:
            annotations = sorted(annotations, key=str)
            ret_val = ret_val.annotate(*annotations[:annotation_limit])
        return {ret_val}

    def __eq__(self, other) -> bool:
        if not isinstance(other, MultiValues):
            return False
        if self._single_value is not None and other._single_value is not None:
            return self._single_value is other._single_value
        if self._single_value is not None and other._single_value is None:
            return False
        if self._single_value is None and other._single_value is not None:
            return False
        assert self._values is not None
        assert other._values is not None
        if set(self._values.keys()) != set(other._values.keys()):
            return False
        return all(self._values[k] == other._values[k] for k in self._values)

    def __repr__(self):
        if self._single_value is not None:
            return f"<{self.__class__.__name__}({self._single_value})>"
        return f"<{self.__class__.__name__}({self._values})>"

    def __contains__(self, offset: int) -> bool:
        if self._single_value is not None:
            return offset == 0
        assert self._values is not None
        return offset in self._values

    def __getitem__(self, offset: int) -> set[claripy.ast.BV]:
        if self._single_value is not None:
            if offset == 0:
                return {self._single_value}
            raise KeyError(offset)
        assert self._values is not None
        return self._values[offset]

    def keys(self) -> set[int]:
        if self._single_value is not None:
            return {0}
        assert self._values is not None
        return set(self._values.keys())

    def values(self) -> Iterator[set[claripy.ast.BV]]:
        if self._single_value is not None:
            yield {self._single_value}
        else:
            assert self._values is not None
            yield from self._values.values()

    def items(self) -> Iterator[tuple[int, set[claripy.ast.BV]]]:
        if self._single_value is not None:
            yield 0, {self._single_value}
        else:
            assert self._values is not None
            yield from self._values.items()

    def count(self) -> int:
        if self._single_value is not None:
            return 1
        assert self._values is not None
        return len(self._values)

    def extract(self, offset: int, length: int, endness: str) -> MultiValues:
        end = offset + length
        result = MultiValues(claripy.BVV(b""))
        for obj_offset, values in self.items():
            if obj_offset >= end:
                break
            for value in values:
                obj_length = len(value) // 8
                if obj_offset + obj_length < offset:
                    continue

                slice_start = max(0, offset - obj_offset)
                slice_end = min(obj_length, end - obj_offset)
                sliced = bv_slice(value, slice_start, slice_end - slice_start, endness == archinfo.Endness.LE, 8)
                if len(sliced):
                    result.add_value(max(0, obj_offset - offset), sliced)

        return result

    def concat(self, other: MultiValues | claripy.ast.BV | bytes) -> MultiValues:
        if isinstance(other, (bytes, bytearray, memoryview)):
            other = claripy.BVV(other)
        if isinstance(other, claripy.ast.BV):
            other = MultiValues(other)
        offset = len(self) // 8
        result = MultiValues(self)
        for k, v in other.items():
            for v2 in v:
                result.add_value(k + offset, v2)
        return result

    #
    # Private methods
    #

    def _adjacent_offset(self, offset: int, before: bool = True) -> int | None:
        """
        Find the offset that is right before or after the given offset.

        :param offset:  The specified offset.
        :param before:  True if we want to find the offset right before the specified offset, False if we want to find
                        the offset right after the specified offset.
        :return:        The adjacent offset as requested. If the requested adjacent offset does not exist, return None.
        """

        sorted_offsets = sorted(self._values.keys()) if self._values is not None else [0]

        for i, off in enumerate(sorted_offsets):
            if off == offset:
                if before:
                    return sorted_offsets[i - 1] if i > 0 else None
                return sorted_offsets[i + 1] if i + 1 < len(sorted_offsets) else None
            if off > offset:
                # we missed it...
                return None
        return None
