from __future__ import annotations

import contextlib
import logging
from contextvars import ContextVar
from functools import wraps
from typing import TYPE_CHECKING, Any, ClassVar, cast

import angr
from angr.misc.ux import once

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

    from angr.sim_state import SimState


l = logging.getLogger(name=__name__)

# The memoization dictionary for the plugin copy operation currently in progress, mapping id(original) to the
# copied instance. It is managed entirely by copy_context() and the wrapper installed around plugin copy()
# implementations - plugin code should never need to touch it.
_copy_memo: ContextVar[dict[int, Any] | None] = ContextVar("simstateplugin_copy_memo", default=None)

_MISSING = object()


@contextlib.contextmanager
def copy_context() -> Iterator[None]:
    """
    A context manager that makes all ``SimStatePlugin.copy()`` calls within it preserve shared object identity: if
    the same plugin object is reachable through multiple paths (for example, a SimFile referenced by both the
    filesystem and a file descriptor), it will only be copied once, and every reference in the copies will point to
    that single new instance.

    ``SimState.copy()`` wraps the copying of its plugins in this context; you only need it yourself when copying
    multiple plugins that may share subobjects outside of a full state copy.

    Nesting is a no-op: if a context is already active, it is reused.
    """
    if _copy_memo.get() is not None:
        yield
        return
    token = _copy_memo.set({})
    try:
        yield
    finally:
        _copy_memo.reset(token)


def _memoize_copy(f):
    """
    Wrap a ``copy()`` implementation with the shared-identity bookkeeping. Applied automatically to every ``copy``
    method defined by a SimStatePlugin subclass, so plugin authors never deal with it directly.
    """
    if getattr(f, "__sim_copy_memoized__", False):
        return f

    @wraps(f)
    def copy_wrapper(self):
        memo = _copy_memo.get()
        if memo is None:
            with copy_context():
                return copy_wrapper(self)
        c = memo.get(id(self), _MISSING)
        if c is not _MISSING:
            return c
        c = f(self)
        memo[id(self)] = c
        return c

    copy_wrapper.__sim_copy_memoized__ = True  # type: ignore[attr-defined]
    return copy_wrapper


def _copy_element(v):
    return v.copy() if isinstance(v, SimStatePlugin) else v


def _copy_value(v):
    """
    Copy a single plugin field value for the default copy() implementation. SimStatePlugins are copied recursively,
    plain dicts/lists/sets are shallow-copied with any SimStatePlugin elements copied recursively, and everything
    else is shared by reference.
    """
    if isinstance(v, SimStatePlugin):
        return v.copy()
    t = type(v)
    if t is dict:
        return {k: _copy_element(x) for k, x in v.items()}
    if t is list:
        return [_copy_element(x) for x in v]
    if t is set:
        return {_copy_element(x) for x in v}
    return v


class SimStatePlugin:
    """
    This is a base class for SimState plugins. A SimState plugin will be copied along with the state when the state is
    branched. They are intended to be used for things such as tracking open files, tracking heap details, and providing
    storage and persistence for SimProcedures.

    When a state is copied, each plugin's ``copy()`` method is called. The default implementation copies every field
    of the plugin automatically - see ``copy()`` for the exact semantics and for how to control which fields are
    copied via ``__slots__`` or ``_COPY_FIELDS``. Plugins with special requirements may override ``copy()``; the
    override takes no arguments, and any bookkeeping needed to keep shared objects shared is handled automatically
    by the plugin machinery.
    """

    # Subclasses may set _COPY_FIELDS to explicitly declare which attributes the default copy() implementation
    # should duplicate. Declarations are unioned across the class hierarchy, so a subclass only needs to list the
    # fields it adds. If no class in the hierarchy declares _COPY_FIELDS, fields are discovered automatically from
    # __slots__ declarations and the instance dict.
    _COPY_FIELDS: ClassVar[Sequence[str] | None] = None

    def __init__(self) -> None:
        self.state: SimState[Any, Any] = cast("SimState[Any, Any]", None)

    def __init_subclass__(cls, **kwargs) -> None:
        super().__init_subclass__(**kwargs)
        if "copy" in cls.__dict__:
            cls.copy = _memoize_copy(cls.__dict__["copy"])

    def set_state(self, state) -> None:
        """
        Sets a new state (for example, if the state has been branched)
        """
        self.state = state._get_weakref()

    def __getstate__(self) -> dict[str, Any]:
        d = dict(self.__dict__)
        d["state"] = None
        return d

    def _blank_copy(self):
        """
        Create an uninitialized instance of this plugin's class, with no state attached. Use this at the start of a
        custom ``copy()`` implementation to construct the object to copy into - the fields of the result are entirely
        unset, so make sure your copy method instantiates all of them!
        """
        cls = type(self)
        o = cls.__new__(cls)
        o.state = None  # type: ignore[assignment]
        # if a copy is in progress, immediately publish the blank instance as the copy of this plugin so that any
        # recursive references back to this plugin resolve to it instead of recursing forever
        memo = _copy_memo.get()
        if memo is not None:
            memo.setdefault(id(self), o)
        return o

    @classmethod
    def _copy_class_fields(cls) -> tuple[bool, tuple[str, ...]]:
        """
        Compute (and cache) the class-level field declarations for the default copy() implementation: the union of
        all __slots__ and _COPY_FIELDS declarations across the class hierarchy. The returned flag says whether any
        _COPY_FIELDS declaration exists, in which case the instance dict is not swept for additional fields.
        """
        cached = cls.__dict__.get("__sim_copy_class_fields__")
        if cached is not None:
            return cached
        names: list[str] = []
        seen: set[str] = set()
        explicit = False
        for klass in reversed(cls.__mro__):
            for source in (klass.__dict__.get("__slots__", ()), klass.__dict__.get("_COPY_FIELDS") or ()):
                for name in (source,) if isinstance(source, str) else source:
                    if name not in seen and name not in ("state", "__dict__", "__weakref__"):
                        seen.add(name)
                        names.append(name)
            if klass.__dict__.get("_COPY_FIELDS") is not None:
                explicit = True
        result = (explicit, tuple(names))
        cls.__sim_copy_class_fields__ = result  # type: ignore[attr-defined]
        return result

    @_memoize_copy
    def copy(self):
        """
        Return a copy of the plugin without any state attached.

        The default implementation copies every field of the plugin. The set of fields is the union of all
        ``__slots__`` and ``_COPY_FIELDS`` declarations across the class hierarchy; if no class declares
        ``_COPY_FIELDS``, everything in the instance dict is included as well, so plain plugins need no declarations
        at all. Each field value is copied with these rules: SimStatePlugin values are copied recursively, plain dicts/lists/sets
        are shallow-copied with SimStatePlugin elements copied recursively, and all other values are shared by
        reference.

        Override this method if your plugin needs different semantics for some fields. Overrides take no arguments
        and should build their result on top of ``self._blank_copy()`` (or a super().copy() call, if a parent class
        provides a suitable copy implementation). Shared-identity bookkeeping is automatic: while a state is being
        copied, a plugin object referenced from multiple places is only ever copied once, no matter how many times
        its ``copy()`` gets called.
        """
        o = self._blank_copy()
        explicit, fields = self._copy_class_fields()
        for name in fields:
            v = getattr(self, name, _MISSING)
            if v is not _MISSING:
                setattr(o, name, _copy_value(v))
        if not explicit:
            for name, v in self.__dict__.items():
                if name == "state" or name in fields:
                    continue
                setattr(o, name, _copy_value(v))
        return o

    def merge(self, others, merge_conditions, common_ancestor=None):  # pylint:disable=unused-argument
        """
        Should merge the state plugin with the provided others. This will be called by ``state.merge()`` after copying
        the target state, so this should mutate the current instance to merge with the others.

        Note that when multiple instances of a single plugin object (for example, a file) are referenced in the state,
        it is important that merge only ever be called once. This should be solved by designating one of the plugin's
        referees as the "real owner", who should be the one to actually merge it. This technique doesn't work to
        resolve the similar issue that arises during copying because merging doesn't produce a new reference to insert.

        There will be n ``others`` and n+1 merge conditions, since the first condition corresponds to self.
        To match elements up to conditions, say ``zip([self] + others, merge_conditions)``

        When implementing this, make sure that you "deepen" both ``others`` and ``common_ancestor`` before calling
        sub-elements' merge methods, e.g.

        .. code-block:: python

           self.foo.merge(
               [o.foo for o in others],
               merge_conditions,
               common_ancestor=common_ancestor.foo if common_ancestor is not None else None
           )

        During static analysis, merge_conditions can be None, in which case you should use
        ``state.solver.union(values)``.
        TODO: fish please make this less bullshit

        There is a utility ``claripy.ite_cases`` which will help with constructing arbitrarily large merged ASTs.
        Use it like ``self.bar = claripy.ite_cases(zip(conditions[1:], [o.bar for o in others]), self.bar)``

        :param others: the other state plugins to merge with
        :param merge_conditions: a symbolic condition for each of the plugins
        :param common_ancestor: a common ancestor of this plugin and the others being merged
        :returns: True if the state plugins are actually merged.
        :rtype: bool
        """
        raise NotImplementedError(f"merge() not implement for {self.__class__.__name__}")

    @classmethod
    def register_default(cls, name: str, xtr: type[SimStatePlugin] | str | None = None) -> None:
        if cls is SimStatePlugin:
            if once("simstateplugin_register_default deprecation"):
                l.critical(
                    "SimStatePlugin.register_default(name, cls) is deprecated, "
                    "please use SimState.register_default(name)"
                )

            if xtr is None or isinstance(xtr, str):
                raise TypeError(
                    "When calling SimStatePlugin.register_default, "
                    "the plugin class must be provided as the second argument."
                )

            angr.sim_state.SimState.register_default(name, xtr)

        else:
            if xtr is cls:
                if once("simstateplugin_register_default deprecation case 2"):
                    l.critical(
                        "SimStatePlugin.register_default(name, cls) is deprecated, "
                        "please use cls.register_default(name)"
                    )
                xtr = None
            elif not isinstance(xtr, str) and xtr is not None:
                raise TypeError(
                    "When calling a plugin subclass's register_default, "
                    "the second argument must be completely omitted or a preset string."
                )

            angr.sim_state.SimState.register_default(name, cls, xtr if xtr is not None else "default")

    def init_state(self) -> None:
        """
        Use this function to perform any initialization on the state at plugin-add time
        """
