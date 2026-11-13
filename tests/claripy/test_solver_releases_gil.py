from __future__ import annotations

import threading
import time
import unittest

from angr import claripy

# How long each slow query runs: the solver's timeout, in milliseconds.
SOLVE_MS = 300


def slow_solver(name):
    """A solver holding a factoring problem Z3 cannot finish, so a query runs until the timeout."""
    x = claripy.BVS(f"{name}_x", 64)
    y = claripy.BVS(f"{name}_y", 64)
    s = claripy.Solver(timeout=SOLVE_MS)
    s.add(x.zero_extend(64) * y.zero_extend(64) == (2**61 - 1) * (2**62 - 57))
    s.add(x > 1)
    s.add(y > 1)
    return s, x, y


class Ticker:
    """A thread that records the time about every millisecond, whenever it gets to run."""

    def __init__(self):
        self.ticks = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        while not self._stop.is_set():
            self.ticks.append(time.monotonic())
            time.sleep(0.001)

    def __enter__(self):
        self._thread.start()
        # Make sure the thread is up and ticking before anything is measured.
        while not self.ticks:
            time.sleep(0.001)
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._thread.join()

    def ticks_between(self, start, end):
        return sum(1 for t in self.ticks if start < t < end)


class TestSolverReleasesGil(unittest.TestCase):
    """Solver queries release the GIL, so other Python threads run during a solve."""

    def assert_other_threads_run_during(self, query):
        with Ticker() as ticker:
            start = time.monotonic()
            with self.assertRaises(claripy.ClaripySolverInterruptError):
                query()
            end = time.monotonic()
        # The query is one call into the solver that lasts SOLVE_MS. If it held
        # the GIL throughout, the ticker could at best run once on either side
        # of it; when it releases the GIL, the ticker runs every millisecond.
        self.assertGreaterEqual(end - start, SOLVE_MS / 1000 / 2)
        self.assertGreaterEqual(ticker.ticks_between(start, end), 20)

    def test_satisfiable(self):
        s, _, _ = slow_solver("gil_satisfiable")
        self.assert_other_threads_run_during(s.satisfiable)

    def test_satisfiable_with_extra_constraints(self):
        s, x, _ = slow_solver("gil_extra")
        self.assert_other_threads_run_during(lambda: s.satisfiable(extra_constraints=[x != 3]))

    def test_eval(self):
        s, x, _ = slow_solver("gil_eval")
        self.assert_other_threads_run_during(lambda: s.eval(x, 1))

    def test_batch_eval(self):
        s, x, y = slow_solver("gil_batch_eval")
        self.assert_other_threads_run_during(lambda: s.batch_eval([x, y], 1))

    def test_has_false(self):
        s, x, y = slow_solver("gil_has_false")
        self.assert_other_threads_run_during(lambda: s.has_false(x == y + 1))

    def test_solver_busy_in_another_thread(self):
        """Using a solver while another thread runs a query on it raises instead of waiting or crashing."""
        s, _, _ = slow_solver("gil_busy")
        outcome = []

        def solve():
            try:
                outcome.append(s.satisfiable())
            except claripy.ClaripySolverInterruptError as e:
                outcome.append(e)

        thread = threading.Thread(target=solve)
        thread.start()
        # Probe with a cheap call until the other thread is inside its query,
        # which then keeps the solver busy for the rest of SOLVE_MS.
        busy = False
        while thread.is_alive() and not busy:
            try:
                s.branch()
            except RuntimeError:
                busy = True
        self.assertTrue(busy)
        with self.assertRaises(RuntimeError):
            s.satisfiable()
        thread.join()
        # The query that was running is unaffected.
        self.assertEqual(len(outcome), 1)
        self.assertIsInstance(outcome[0], claripy.ClaripySolverInterruptError)

    def test_results_unchanged_across_threads(self):
        """Solvers used from several threads at once still answer correctly."""
        errors = []

        def work(i):
            try:
                x = claripy.BVS(f"gil_thread_{i}", 32)
                s = claripy.Solver()
                s.add(x * 3 == 3 * (i + 7))
                s.add(x < 1000)
                for _ in range(20):
                    assert s.satisfiable()
                    assert s.eval(x, 2) == [i + 7]
                    assert s.min(x) == i + 7
                    assert s.max(x, extra_constraints=[x != 0]) == i + 7
                    assert s.has_true(x == i + 7)
                    assert not s.has_false(x == i + 7)
                    assert not s.is_true(x == i + 8)
                    assert s.solution(x, i + 7)
                    assert not s.solution(x, i + 8)
            except Exception as e:  # pylint:disable=broad-exception-caught
                errors.append(e)

        threads = [threading.Thread(target=work, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
