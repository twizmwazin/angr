Type checking
=============

angr is type-checked with `pyright <https://github.com/microsoft/pyright>`_. The configuration lives
in ``pyrightconfig.json`` at the repository root; it pins the Python version and the checking mode so
that a local run and a CI run agree.

angr ships a ``py.typed`` marker, which means its annotations are part of its public API. Downstream
projects — angr-management, angrop, patcherex — type-check against them, so a wrong annotation is a
bug in the same sense that a wrong docstring is.

Running the checker
-------------------

.. code-block:: bash

   python scripts/typecheck.py            # compare against the baseline (this is what CI runs)
   python scripts/typecheck.py --stats    # current error counts, broken down by rule
   python scripts/typecheck.py --update   # lock in an improvement

The first form exits non-zero if any ``(file, rule)`` pair produces more diagnostics than
``pyright-baseline.json`` allows.

The baseline
------------

angr has a large stock of pre-existing type errors. Rather than suppress them, they are recorded in
``pyright-baseline.json`` as a ledger of ``(file, rule) -> count``. The ledger stores counts, not line
numbers, so editing a file above an existing error does not invalidate it.

The ledger only ever shrinks: ``--update`` refuses to write a baseline whose total is larger than the
one it replaces. If your change legitimately introduces an error that cannot be avoided, say why in
the pull request and run ``--update``; reviewers should treat that as a change requiring
justification, not a formality.

Note that tightening a declaration often *reveals* errors at its call sites — that is the checker
working, not a regression in your change. Fix what it surfaces, or explain why it is a pre-existing
problem being made visible.

Do not silence errors
---------------------

``# type: ignore`` and ``# pyright: ignore`` are a last resort, not a fix. Before reaching for one,
work out which *declaration* is wrong — most of angr's type errors come from a handful of over-wide
or missing declarations, and fixing one of those removes errors by the dozen. In particular:

* Do not annotate something as ``Any`` or ``object`` to make a diagnostic go away.
* Do not use ``cast()`` to launder a value whose type you have not established.
* Do not scatter ``assert x is not None`` at call sites when the real problem is that the attribute
  should not have been ``Optional`` in the first place. An ``assert`` is fine where it records a
  genuine invariant at the point that invariant is established.
* Do not widen a base-class signature to ``*args, **kwargs`` just to make an override compatible.

If you do need a suppression, scope it to the specific rule and say why::

    foo = bar()  # pyright: ignore[reportAttributeAccessIssue]  # protobuf gencode, see #1234

A bare ``# type: ignore`` with no rule code suppresses everything, including errors introduced later
by unrelated edits.

Annotating new code
-------------------

New and substantially rewritten code should annotate its parameters and return types. Most of angr
predates this expectation — only about a quarter of its functions currently declare a return type —
so the rule is applied to what you touch, not to the file you touch it in.

Use the modern syntax throughout: ``X | None`` rather than ``Optional[X]``, PEP 695 generics
(``class Foo[T]:``, ``def f[T](...)``) rather than ``TypeVar``, and built-in generics (``list[int]``)
rather than ``typing.List``. Every module starts with ``from __future__ import annotations``, which
ruff enforces.
