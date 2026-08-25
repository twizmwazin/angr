from __future__ import annotations

from typing import TYPE_CHECKING, Any

from angr import engines
from angr.errors import AngrError, AngrExplorationTechniqueError, SimError

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    from angr.sim_state import SimState


def condition_to_lambda(
    condition: int | Iterable[int] | Callable[[SimState], Any] | None, default: bool = False
) -> tuple[Callable[[SimState], Any], set[int] | None]:
    """
    Translates an integer, set, list or function into a lambda that checks if state's current basic block matches
    some condition.

    :param condition:   An integer, set, list or lambda to convert to a lambda.
    :param default:     The default return value of the lambda (in case condition is None). Default: false.

    :returns:           A tuple of two items: a lambda that takes a state and returns the set of addresses that it
                        matched from the condition, and a set that contains the normalized set of addresses to stop
                        at, or None if no addresses were provided statically.
    """
    condition_function: Callable[[SimState], Any]
    static_addrs: set[int] | None

    if condition is None:

        def condition_default(state: SimState) -> bool:
            return default

        condition_function = condition_default
        static_addrs = set()

    elif isinstance(condition, int):
        return condition_to_lambda((condition,))

    elif isinstance(condition, (tuple, set, list)):
        addrs = set(condition)

        def condition_static(state: SimState) -> set[int] | bool:
            if state.addr in addrs:
                # returning {state.addr} instead of True to properly handle find/avoid conflicts
                return {state.addr}

            project = state.project
            if project is None or not isinstance(project.factory.default_engine, engines.vex.VEXLifter):
                return False
            if isinstance(state.callstack, engines.ail.callstack.AILCallStack):
                return False

            try:
                # If the address is not in the set (which could mean it is
                # not at the top of a block), check directly in the blocks
                # (Blocks are repeatedly created for every check, but with
                # the IRSB cache in angr lifter it should be OK.)
                return addrs.intersection(set(state.block().instruction_addrs))
            except (AngrError, SimError):
                return False

        condition_function = condition_static
        static_addrs = addrs

    elif callable(condition):
        condition_function = condition
        static_addrs = None
    else:
        raise AngrExplorationTechniqueError(
            f"ExplorationTechnique is unable to convert given type ({condition.__class__}) to a callable condition function."
        )

    return condition_function, static_addrs
