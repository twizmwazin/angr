"""Type stubs for ``angr.rustylib.claripy.errors``.

The claripy exception hierarchy.

Note: the ``InvalidExtractBounds`` binding refers to a class whose
``__name__`` is ``InvalidExtractBoundsError``; the module attribute is
spelled without the ``Error`` suffix.
"""

class ClaripyError(Exception): ...
class ClaripyTypeError(ClaripyError): ...
class UnsatError(ClaripyError): ...
class ClaripyFrontendError(ClaripyError): ...
class ClaripySolverInterruptError(ClaripyError): ...
class ClaripyOperationError(ClaripyError): ...
class ClaripyZeroDivisionError(ClaripyOperationError): ...
class InvalidExtractBounds(ClaripyOperationError): ...

__all__ = [
    "ClaripyError",
    "ClaripyFrontendError",
    "ClaripyOperationError",
    "ClaripySolverInterruptError",
    "ClaripyTypeError",
    "ClaripyZeroDivisionError",
    "InvalidExtractBounds",
    "UnsatError",
]
