from __future__ import annotations

import logging
from typing import Any

from angr.sim_state import SimState

from .plugin import SimStatePlugin

l = logging.getLogger(name=__name__)


class SimStateGlobals(SimStatePlugin):
    def __init__(self, backer: dict[Any, Any] | None = None):
        super().__init__()
        self._backer: dict[Any, Any] = backer if backer is not None else {}

    def set_state(self, state):
        pass

    def merge(self, others, merge_conditions, common_ancestor=None):  # pylint: disable=unused-argument
        for other in others:
            for k in other:
                if k not in self:
                    self[k] = other[k]

        return True

    def __iter__(self):
        return iter(self._backer)

    def __getitem__(self, k) -> Any:
        return self._backer[k]

    def __setitem__(self, k, v) -> None:
        self._backer[k] = v

    def __delitem__(self, k) -> None:
        del self._backer[k]

    def __contains__(self, k) -> bool:
        return k in self._backer

    def keys(self):
        return self._backer.keys()

    def values(self):
        return self._backer.values()

    def items(self):
        return self._backer.items()

    def get(self, k, alt: Any = None) -> Any:
        return self._backer.get(k, alt)

    def pop(self, k, alt: Any = None) -> Any:
        return self._backer.pop(k, alt)

    @SimStatePlugin.memo
    def copy(self, memo):  # pylint: disable=unused-argument
        return SimStateGlobals(dict(self._backer))


SimState.register_default("globals", SimStateGlobals)
