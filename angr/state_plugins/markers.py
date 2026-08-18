"""Spelling "a state which carries plugins X, Y and Z" in an annotation.

Most of :class:`~angr.sim_state.SimState`'s plugins are situational. ``cgc`` is meaningful only for
a DECREE binary, ``javavm_classloader`` only for a Java project, ``unicorn`` only when that engine is
in use, ``fs`` only where there is a filesystem to simulate. Those plugins are deliberately *not*
declared on ``SimState``: doing so would claim every state has them, and would let ``state.cgc``
type-check on a Linux binary.

An API that needs some of them says so inline, in one annotation, in any order::

    def rewind(state: StateWith[Unicorn | SimStateCGC]) -> None:
        state.plugin(UNICORN).stop(STOP.STOP_NORMAL)
        state.plugin(CGC).max_receive_size
        state.solver.eval(state.regs.pc)          # the ordinary state API, unaffected

and a caller turns a plain state into one in a single call, which raises if a plugin is missing::

    rewind(state.require(UNICORN, CGC))

``StateWith``'s plugin parameter is **contravariant**, which is what makes this work: a state
promising more satisfies a signature asking for less. ``StateWith[Unicorn | SimStateCGC]`` is
accepted where ``StateWith[Unicorn]`` is wanted, but not the other way round, and a bare ``SimState``
is accepted by neither. That is subset semantics, spelled with a union, with no combination classes
to declare and no ordering to remember.

Plugins are named by a :class:`PluginKey` rather than by their class, because the class is not a
unique key -- ``memory``, ``registers`` and ``sym_memory`` are all ``DefaultMemory``. ``PluginKey``
is invariant on purpose: were it covariant, ``require(UNICORN, CGC)`` could silently widen to satisfy
a signature wanting a third plugin.

Why not one marker class per plugin
-----------------------------------

That works, and composes only by declaring a class per combination -- ``class Both(StateWithUnicorn,
StateWithCGC)`` -- which is not a quick way to say "I need X, Y and Z". A single generic marker
carrying one plugin cannot be combined at all: ``class Both(StateWith1[Unicorn],
StateWith1[SimStateCGC])`` is a duplicate base class, statically and at runtime. A ``TypeVarTuple``
form is worse still -- it matches positionally and invariantly, so a state carrying more plugins
fails a signature asking for fewer.

The cost of the contravariant form is that the plugin is reached through ``state.plugin(KEY)``
rather than ``state.unicorn``. Only a declared attribute can give the latter, and declaring it is
exactly the claim -- "every state has this" -- that this module exists to avoid.
"""

from __future__ import annotations

from typing import Any, Generic

from typing_extensions import TypeVar

from angr.sim_state import SimState

from .cgc import SimStateCGC
from .debug_variables import SimDebugVariablePlugin
from .filesystem import SimFilesystem
from .gdb import GDB
from .heap.heap_base import SimHeapBase
from .icicle import SimStateIcicle
from .javavm_classloader import SimJavaVmClassloader
from .jni_references import SimStateJNIReferences
from .libc import SimStateLibc
from .loop_data import SimStateLoopData
from .plugin import SimStatePlugin
from .posix import SimSystemPosix
from .preconstrainer import SimStatePreconstrainer
from .symbolizer import SimSymbolizer
from .uc_manager import SimUCManager
from .unicorn_engine import Unicorn

# Contravariant: a state promising more plugins satisfies a signature asking for fewer.
_PluginT_contra = TypeVar("_PluginT_contra", bound=SimStatePlugin, contravariant=True)
_IPTypeConc = TypeVar("_IPTypeConc", default=Any)
_IPTypeSym = TypeVar("_IPTypeSym", default=Any)


class PluginKey[PluginT: SimStatePlugin]:
    """The registry name of a state plugin, carrying its type.

    Instances are module-level constants; see the keys defined at the bottom of this module.

    The parameter must infer as *invariant*: were it covariant, ``require(UNICORN, CGC)`` could
    silently widen to satisfy a signature wanting a third plugin. ``_invariance_marker`` puts
    ``PluginT`` in both an input and an output position, which is what forces that.
    """

    __slots__ = ("cls", "name")

    def __init__(self, name: str, cls: type[PluginT]) -> None:
        self.name = name
        self.cls = cls

    def _invariance_marker(self, plugin: PluginT) -> PluginT:
        """Never called; exists so that ``PluginT`` infers as invariant rather than covariant."""
        return plugin

    def of(self, state: StateWith[PluginT, Any, Any]) -> PluginT:
        """Return this plugin from a state whose type promises it.

        The accessor lives on the key rather than on the state because ``PluginT`` is then already
        fixed by the key -- ``UNICORN`` is a ``PluginKey[Unicorn]`` -- so it cannot be solved from
        the state's whole union instead.
        """
        return state.get_plugin(self.name)

    def __repr__(self) -> str:
        return f"<PluginKey {self.name}>"


class StateWith(SimState[_IPTypeConc, _IPTypeSym], Generic[_PluginT_contra, _IPTypeConc, _IPTypeSym]):
    """A :class:`~angr.sim_state.SimState` that carries the plugins named by its parameter.

    Write the requirement as a union -- ``StateWith[Unicorn | SimStateCGC]``. Obtain one with
    :meth:`~angr.sim_state.SimState.require`. The remaining two parameters are ``SimState``'s own and
    default to ``Any``, so they only need spelling when the instruction-pointer types matter.

    This is an annotation, not a class to instantiate.
    """

    __slots__ = ()

    def __init__(self, *args, **kwargs) -> None:
        raise TypeError(
            "StateWith is an annotation for a SimState carrying particular plugins, not a class to "
            "instantiate. Build a SimState and call require() on it."
        )


CGC = PluginKey("cgc", SimStateCGC)
DVARS = PluginKey("dvars", SimDebugVariablePlugin)
FS = PluginKey("fs", SimFilesystem)
GDB_ = PluginKey("gdb", GDB)
HEAP = PluginKey("heap", SimHeapBase)
ICICLE = PluginKey("icicle", SimStateIcicle)
JAVAVM_CLASSLOADER = PluginKey("javavm_classloader", SimJavaVmClassloader)
JNI_REFERENCES = PluginKey("jni_references", SimStateJNIReferences)
LIBC = PluginKey("libc", SimStateLibc)
LOOP_DATA = PluginKey("loop_data", SimStateLoopData)
POSIX = PluginKey("posix", SimSystemPosix)
PRECONSTRAINER = PluginKey("preconstrainer", SimStatePreconstrainer)
SYMBOLIZER = PluginKey("symbolizer", SimSymbolizer)
UC_MANAGER = PluginKey("uc_manager", SimUCManager)
UNICORN = PluginKey("unicorn", Unicorn)


__all__ = (
    "CGC",
    "DVARS",
    "FS",
    "GDB_",
    "HEAP",
    "ICICLE",
    "JAVAVM_CLASSLOADER",
    "JNI_REFERENCES",
    "LIBC",
    "LOOP_DATA",
    "POSIX",
    "PRECONSTRAINER",
    "SYMBOLIZER",
    "UC_MANAGER",
    "UNICORN",
    "PluginKey",
    "StateWith",
)
