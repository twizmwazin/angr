"""Architecture-specific exception entry/exit semantics.

A :class:`SimException` describes how to transfer control into an exception
handler and how to detect and return from one for a given architecture and
platform. It is the exception-handling analogue of :class:`SimCC` (calling
conventions).

The generic pending-exception queue lives in
:class:`angr.state_plugins.SimStateExceptions`; it knows nothing about stack
frames or EXC_RETURN values. The engine integration (an ``ExceptionMixin``)
consults the queue and delegates to a :class:`SimException` subclass to
perform the arch-specific frame manipulation.

Usage
-----

Look up the model for a state::

    sim_exc = default_exception_model(state.arch.name)
    model = sim_exc(state.arch)

Enter an exception::

    state = model.enter(state, pending_exception)

Detect and exit::

    if model.is_return_point(state):
        state = model.exit(state)
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import ClassVar, TYPE_CHECKING

import archinfo
import claripy

if TYPE_CHECKING:
    from angr.sim_state import SimState
    from angr.state_plugins.exceptions import PendingException

log = logging.getLogger(__name__)


class SimException(ABC):
    """Abstract exception-handling model for a single architecture/platform.

    Subclasses implement the arch-specific frame format and return-detection
    rules. They are constructed with an :class:`archinfo.Arch` instance and
    apply to :class:`angr.SimState` values of that architecture.

    The model is stateless — methods return modified states rather than
    mutating instance data. This makes it safe to share a single model
    across many states.
    """

    #: Architectures this model applies to (class-level attribute, like ``SimCC``).
    ARCH: ClassVar[type[archinfo.Arch]]

    def __init__(self, arch: archinfo.Arch):
        self.arch = arch

    @abstractmethod
    def enter(self, state: SimState, exc: PendingException) -> SimState:
        """Transfer execution into an exception handler.

        Saves the interrupted context (according to arch-specific rules) and
        redirects the state's PC to the handler. The resulting state, when
        resumed, begins executing the handler's first instruction.

        :param state: The state being preempted.
        :param exc:   The exception being dispatched. ``exc.payload`` is the
                      arch/source-specific data (handler address, vector
                      number, etc.); subclasses document what they expect.
        :returns: A new state with the handler as its next instruction.
        """

    @abstractmethod
    def is_return_point(self, state: SimState) -> bool:
        """Return ``True`` if the state is at an exception-return point.

        Examples: Cortex-M PC matching an ``EXC_RETURN`` magic value, x86
        ``IRET`` about to execute, RISC-V ``MRET`` CSR machinery, POSIX
        ``sigreturn`` syscall entry. The caller checks this after each
        execution step to decide whether to invoke :meth:`exit`.
        """

    @abstractmethod
    def exit(self, state: SimState) -> SimState:
        """Restore the preempted context and resume it.

        Inverse of :meth:`enter`. Produces a state that resumes the code
        that was interrupted when the exception fired.
        """


# ─────────────────────────────────────────────────────────────────────────────
# Cortex-M implementation
# ─────────────────────────────────────────────────────────────────────────────


#: EXC_RETURN values used on Cortex-M to signal exception return. The
#: upper 28 bits are always 0xFFFFFFF; the low nibble selects the return
#: mode (thread/handler, MSP/PSP, basic/FP frame).
_CORTEX_M_EXC_RETURN_MASK = 0xFFFF_FFF0
_CORTEX_M_EXC_RETURN_PREFIX = 0xFFFF_FFF0
#: Return to Thread mode with MSP, basic frame (8 words).
EXC_RETURN_HANDLER_MSP = 0xFFFF_FFF1
EXC_RETURN_THREAD_MSP = 0xFFFF_FFF9
EXC_RETURN_THREAD_PSP = 0xFFFF_FFFD
#: Only the exact EXC_RETURN values defined by ARMv7-M should trigger
#: exception return. A PC in the 0xFFFFFFF0-F range with other low bits
#: is just garbage that happens to land there (e.g. a `bx lr` with a
#: corrupted lr) — treating it as EXC_RETURN would pop random stack
#: bytes and then typically loop through more garbage states.
_VALID_EXC_RETURN_VALUES = frozenset({
    EXC_RETURN_HANDLER_MSP,
    EXC_RETURN_THREAD_MSP,
    EXC_RETURN_THREAD_PSP,
    0xFFFF_FFE1,  # Handler-mode MSP with FP frame
    0xFFFF_FFE9,  # Thread-mode MSP with FP frame
    0xFFFF_FFED,  # Thread-mode PSP with FP frame
})


class CortexMPendingException:
    """Payload for a Cortex-M exception.

    :ivar handler:  Absolute address of the handler (from the vector table).
    :ivar vector:   Exception/interrupt number (optional, for logging).
    """

    __slots__ = ("handler", "vector")

    def __init__(self, handler: int, vector: int | None = None):
        self.handler = handler
        self.vector = vector


class SimExceptionCortexM(SimException):
    """Cortex-M hardware exception model.

    Entry
    -----
    On exception entry the hardware pushes an 8-word frame on the active
    stack (MSP, since Thread-mode with PSP isn't emulated):

    .. code-block:: none

        [SP+0x1C]  xPSR
        [SP+0x18]  ReturnAddress (PC | T-bit)
        [SP+0x14]  LR
        [SP+0x10]  R12
        [SP+0x0C]  R3
        [SP+0x08]  R2
        [SP+0x04]  R1
        [SP+0x00]  R0

    LR is loaded with ``EXC_RETURN_THREAD_MSP`` (0xFFFFFFF9) and PC jumps
    to the handler address.

    Return
    ------
    Exception return is detected by the PC reaching an EXC_RETURN magic
    value (0xFFFFFFFx). The state's ``exit`` pops the 8-word frame and
    restores PC to the saved return address.

    The payload passed to :meth:`enter` must be a :class:`CortexMPendingException`.
    """

    ARCH = archinfo.ArchARMCortexM

    # Offsets of each word in the hardware exception frame.
    _FRAME_LAYOUT = ("r0", "r1", "r2", "r3", "r12", "lr", "pc", "xpsr")
    _FRAME_SIZE = 8 * 4  # 32 bytes

    def enter(self, state: SimState, exc: PendingException) -> SimState:
        payload = exc.payload
        if not isinstance(payload, CortexMPendingException):
            raise TypeError(
                f"SimExceptionCortexM expects a CortexMPendingException payload, got {type(payload).__name__}"
            )

        new_state = state.copy()

        # Gather the hardware-stacked registers.
        r0 = new_state.regs.r0
        r1 = new_state.regs.r1
        r2 = new_state.regs.r2
        r3 = new_state.regs.r3
        r12 = new_state.regs.r12
        lr = new_state.regs.lr
        # Return address is the current PC with the Thumb bit set.
        return_addr = new_state.regs.pc | 1
        # xPSR: set the T-bit (bit 24). We don't model the other flags.
        xpsr = claripy.BVV(1 << 24, 32)

        # Push the frame. SP decreases, frame[0] at the lowest address.
        sp = new_state.solver.eval(new_state.regs.sp) - self._FRAME_SIZE
        frame_regs = (r0, r1, r2, r3, r12, lr, return_addr, xpsr)
        for i, value in enumerate(frame_regs):
            new_state.memory.store(
                sp + i * 4, value, size=4, endness=self.arch.memory_endness,
            )

        new_state.regs.sp = sp
        new_state.regs.lr = EXC_RETURN_THREAD_MSP
        # Clear Thumb bit from the handler address — angr tracks Thumb mode
        # via the LSB of PC on Cortex-M, but the actual instruction address
        # must be even. We set the LSB back via the state setter below.
        new_state.regs.pc = payload.handler | 1

        log.debug(
            "Cortex-M exception entry: handler=0x%08X vector=%s, SP=0x%08X",
            payload.handler, payload.vector, sp,
        )
        return new_state

    def is_return_point(self, state: SimState) -> bool:
        try:
            pc = state.solver.eval(state.regs.pc)
        except Exception:  # pylint: disable=broad-except
            return False
        return pc in _VALID_EXC_RETURN_VALUES

    def exit(self, state: SimState) -> SimState:
        new_state = state.copy()
        sp = new_state.solver.eval(new_state.regs.sp)

        # Pop the 8-word frame, one word at a time so each respects the
        # arch's memory endness correctly.
        words = [
            new_state.memory.load(sp + i * 4, 4, endness=self.arch.memory_endness)
            for i in range(8)
        ]

        new_state.regs.r0 = words[0]
        new_state.regs.r1 = words[1]
        new_state.regs.r2 = words[2]
        new_state.regs.r3 = words[3]
        new_state.regs.r12 = words[4]
        new_state.regs.lr = words[5]
        new_state.regs.pc = words[6]  # Thumb bit preserved in saved value
        new_state.regs.sp = sp + self._FRAME_SIZE
        # words[7] is xPSR — hardware writes it to APSR/IPSR/EPSR on return,
        # but angr doesn't model those sub-registers, so we drop it.

        # The pre-exit state often carries a fault jumpkind (e.g.
        # Ijk_SigSEGV when icicle tried to fetch from the EXC_RETURN
        # magic PC). That fault is subsumed by the exception return —
        # downstream engines resume from the popped PC, which is a
        # normal sequential flow.
        new_state.history.jumpkind = "Ijk_Boring"

        log.debug(
            "Cortex-M exception exit: SP=0x%08X (return addr in popped PC)",
            sp + self._FRAME_SIZE,
        )
        return new_state


# ─────────────────────────────────────────────────────────────────────────────
# Registry (mirrors SimCC's DEFAULT_CC pattern)
# ─────────────────────────────────────────────────────────────────────────────


DEFAULT_EXCEPTION_MODEL: dict[str, dict[str, type[SimException]]] = {
    "ARMCortexM": {"Linux": SimExceptionCortexM, "default": SimExceptionCortexM},
}


def register_default_exception_model(
    arch: str, model: type[SimException], platform: str = "Linux"
) -> None:
    """Register ``model`` as the default for ``arch``/``platform``."""
    if arch not in DEFAULT_EXCEPTION_MODEL:
        DEFAULT_EXCEPTION_MODEL[arch] = {}
    DEFAULT_EXCEPTION_MODEL[arch][platform] = model


def default_exception_model(
    arch: str,
    platform: str | None = "Linux",
    default: type[SimException] | None = None,
) -> type[SimException] | None:
    """Return the default :class:`SimException` class for ``arch``/``platform``.

    :param arch:     The architecture name (e.g., ``"ARMCortexM"``).
    :param platform: The platform name (e.g., ``"Linux"``).
    :param default:  Returned when no model is registered.
    """
    if platform is None:
        platform = "Linux"

    arch_map = DEFAULT_EXCEPTION_MODEL.get(arch)
    if arch_map is None:
        return default

    if platform in arch_map:
        return arch_map[platform]
    if "default" in arch_map:
        return arch_map["default"]
    if "Linux" in arch_map:
        return arch_map["Linux"]
    return default


__all__ = (
    "CortexMPendingException",
    "DEFAULT_EXCEPTION_MODEL",
    "EXC_RETURN_HANDLER_MSP",
    "EXC_RETURN_THREAD_MSP",
    "EXC_RETURN_THREAD_PSP",
    "SimException",
    "SimExceptionCortexM",
    "default_exception_model",
    "register_default_exception_model",
)
