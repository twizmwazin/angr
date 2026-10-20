"""Type stubs for ``angr.rustylib.claripy.annotation``."""

from typing import Any, ClassVar

class Annotation:
    relocatable: ClassVar[bool]
    eliminatable: ClassVar[bool]
    def __init__(self, *args: Any, **kwargs: Any) -> None: ...

class SimplificationAvoidanceAnnotation(Annotation):
    def __init__(self, *args: Any, **kwargs: Any) -> None: ...
    def __reduce__(self) -> tuple[type[SimplificationAvoidanceAnnotation], tuple[()]]: ...

class RegionAnnotation(Annotation):
    @property
    def region_id(self) -> str: ...
    @property
    def region_base_addr(self) -> int: ...
    def __init__(self, region_id: str, region_base_addr: int) -> None: ...
    def __reduce__(self) -> tuple[type[RegionAnnotation], tuple[str, int]]: ...

class UninitializedAnnotation(Annotation):
    def __init__(self, *args: Any, **kwargs: Any) -> None: ...
    def __reduce__(self) -> tuple[type[UninitializedAnnotation], tuple[()]]: ...

__all__ = [
    "Annotation",
    "RegionAnnotation",
    "SimplificationAvoidanceAnnotation",
    "UninitializedAnnotation",
]
