from __future__ import annotations

from .base import BaseStructuredCodeGenerator, IdentType


class DummyStructuredCodeGenerator(BaseStructuredCodeGenerator):
    """
    A dummy structured code generator that only stores user-specified information.
    """

    def __init__(
        self,
        flavor: str,
        expr_comments: dict[int, str] | None = None,
        stmt_comments: dict[int, str] | None = None,
        configuration=None,
        const_formats: dict[IdentType, dict[str, bool]] | None = None,
    ):
        super().__init__(flavor)
        self.expr_comments = expr_comments
        self.stmt_comments = stmt_comments
        self.configuration = configuration
        self.const_formats = const_formats
