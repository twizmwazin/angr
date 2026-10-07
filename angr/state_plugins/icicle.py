from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from angr.sim_state import SimState

from .plugin import SimStatePlugin

if TYPE_CHECKING:
    from angr.rustylib.icicle import Icicle


@dataclass
class IcicleStateTranslationData:
    """
    Describes how the contents of an Icicle VM line up with angr states: which
    registers are synced, which pages are mapped and writable in the VM, and
    the VM's instruction count when the current run started.

    It holds no reference to a state, so keeping it around does not keep any
    state (or its memory) alive.
    """

    registers: set[str]
    mapped_pages: set[int]
    writable_pages: set[int]
    explicit_page_metadata: dict[int, int | None]
    initial_cpu_icount: int
    icicle_arch: str


@dataclass
class IcicleVMRef:
    """Holder shared by reference across plugin copies.

    Lets multiple SimStateIcicle plugins point at the same VM and observe each
    other's advancements via `generation`: each successful engine run bumps
    `generation`, invalidating any plugin still holding the prior value.

    Everything the engine needs to know about the VM lives here rather than on
    the states, because it describes the VM: `base_state` and
    `base_translation_data` describe the VM's snapshot (the state it was built
    from), and `translation_data` describes the VM as the last run left it,
    which only the live state can continue from.
    """

    vm: Icicle
    base_state: SimState[int, int]
    base_translation_data: IcicleStateTranslationData
    translation_data: IcicleStateTranslationData
    generation: int = 0


class SimStateIcicle(SimStatePlugin):
    """Engine-internal plugin for IcicleEngine continuation detection.

    Attached to states produced by ``IcicleEngine.process()``. Owns the VM and
    the metadata the engine needs to decide whether the next call is a
    lightweight continuation or requires a full snapshot restore.
    """

    def __init__(
        self,
        vm_ref: IcicleVMRef | None = None,
        generation: int | None = None,
        dirty_pages: set[int] | None = None,
    ):
        super().__init__()
        self.vm_ref = vm_ref
        self.generation = generation
        self.dirty_pages = dirty_pages if dirty_pages is not None else set()

    @property
    def is_live(self) -> bool:
        """True when the VM is still positioned where this state last left it."""
        return self.vm_ref is not None and self.generation == self.vm_ref.generation

    def set_state(self, state):
        pass  # no weak ref needed

    @SimStatePlugin.memo
    def copy(self, _memo):
        return SimStateIcicle(
            vm_ref=self.vm_ref,
            generation=self.generation,
            dirty_pages=set(self.dirty_pages),
        )

    def merge(self, others, merge_conditions, common_ancestor=None):
        return False


SimState.register_default("icicle", SimStateIcicle)
