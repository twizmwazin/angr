# pylint:disable=missing-class-docstring
from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from angr.storage.memory_mixins.memory_mixin import MemoryMixin
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues


class MultiValueMergerMixin(MemoryMixin):
    def __init__(
        self,
        *args,
        element_limit=5,
        annotation_limit=256,
        top_func=None,
        is_top_func=None,
        phi_maker=None,
        merge_into_top=True,
        **kwargs,
    ):
        self._element_limit = element_limit
        self._annotation_limit = annotation_limit
        self._top_func: Callable = top_func
        self._is_top_func: Callable = is_top_func
        self._phi_maker: Callable | None = phi_maker
        self._merge_into_top = merge_into_top

        super().__init__(*args, **kwargs)

    def store(self, addr, data, size=None, **kwargs):
        # Apply the element limit on the store path too. Merging only happens at control-flow joins, so a
        # straight-line chain of ITEs (e.g., cmovs) would otherwise grow value sets exponentially.
        if isinstance(data, MultiValues):
            data = data.limit(
                self._element_limit,
                self._top_func,
                is_top_func=self._is_top_func if self._merge_into_top else None,
                annotation_limit=self._annotation_limit,
            )
        super().store(addr, data, size=size, **kwargs)

    def _merge_values(self, values: Iterable[tuple[Any, Any]], merged_size: int, **kwargs):
        values_set = {v for v, _ in values}
        if self._phi_maker is not None:
            phi_var = self._phi_maker(values_set)
            if phi_var is not None:
                return {phi_var}

        # try to merge it in the traditional way
        return MultiValues.collapse_values(
            values_set,
            merged_size * self.state.arch.byte_width,
            self._element_limit,
            self._top_func,
            is_top_func=self._is_top_func if self._merge_into_top else None,
            annotation_limit=self._annotation_limit,
        )

    def copy(self, memo=None):
        copied = super().copy(memo)
        copied._element_limit = self._element_limit
        copied._annotation_limit = self._annotation_limit
        copied._top_func = self._top_func
        copied._is_top_func = self._is_top_func
        copied._phi_maker = self._phi_maker
        copied._merge_into_top = self._merge_into_top
        return copied
