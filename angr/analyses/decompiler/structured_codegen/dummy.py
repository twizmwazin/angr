from __future__ import annotations

from typing import TYPE_CHECKING

from .base import BaseStructuredCodeGenerator, IdentType

if TYPE_CHECKING:
    from angr.analyses.decompiler.decompilation_options import DecompilationOption


class DummyStructuredCodeGenerator(BaseStructuredCodeGenerator):
    """
    A dummy structured code generator that only stores user-specified information.
    """

    def __init__(
        self,
        flavor: str,
        expr_comments: dict[int, str] | None = None,
        stmt_comments: dict[int, str] | None = None,
        configuration: list[tuple[DecompilationOption, object]] | None = None,
        const_formats: dict[IdentType, dict[str, bool]] | None = None,
    ):
        # let the base normalise the three comment/format mappings to {} when they are None, instead of storing
        # None over attributes the base declares as plain dicts
        super().__init__(
            flavor,
            expr_comments=expr_comments,
            stmt_comments=stmt_comments,
            const_formats=const_formats,
        )
        self.configuration = configuration
