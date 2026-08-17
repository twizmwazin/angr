#!/usr/bin/env python3
"""
Profile symbolic execution workloads taken from angr's own test suite, and summarize where the time goes.

The workloads mirror the heaviest symbolic-execution tests so that the profile is representative of what CI
actually spends its time on:

- ``fauxware``        tests/sim/test_fauxware.py::test_fauxware (the canonical exploration test)
- ``fauxware_armel``  the same, on a non-x86 architecture (more VEX work per block)
- ``strstr``          tests/sim/exec_func/test_str_funcs.py::test_strstr (symbolic string search)
- ``strtol``          tests/procedures/libc/test_strtol.py::test_strtol (the slowest test in the suite)
- ``veritesting``     tests/exploration_techniques/test_veritesting.py::test_veritesting_a
- ``libc_strings``    tests/procedures/libc/test_string.py-style SimProcedure calls with symbolic arguments
- ``tight_loops``     tests/perf/perf_concrete_execution.py-style engine throughput (no unicorn)
- ``state_copy``      tests/perf/perf_state_copy.py-style fork/store churn

Usage::

    # run every scenario, write <outdir>/<scenario>.prof and print a summary of each
    python tests/perf/profile_symbolic_execution.py /tmp/prof

    # run a subset
    python tests/perf/profile_symbolic_execution.py /tmp/prof fauxware strtol

    # just summarize profiles collected earlier (also works on `python -m cProfile -o` output from pytest)
    python tests/perf/profile_symbolic_execution.py --report /tmp/prof/fauxware.prof

The summary groups self time by component (z3, claripy AST, angr memory mixins, angr engines, ...), which is
what tells you whether a workload is solver-bound or interpreter-bound.
"""

from __future__ import annotations

import argparse
import cProfile
import os
import pstats
import sys
import time
from collections import defaultdict

import claripy

import angr

bin_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "..", "binaries")
test_location = os.path.join(bin_location, "tests")


#
# workloads
#


def fauxware():
    p = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
    results = p.factory.simulation_manager().explore(find=[0x4006ED], avoid=[0x4006AA, 0x4006FD])
    assert results.found[0].posix.dumps(0) == b"\x00" * 9 + b"SOSNEAKY\x00"


def fauxware_armel():
    p = angr.Project(os.path.join(test_location, "armel", "fauxware"), auto_load_libs=False)
    assert p.factory.simulation_manager().explore(find=[0x85F0], avoid=[0x86F8, 0x857C]).found


def strstr():
    p = angr.Project(
        os.path.join(test_location, "x86_64", "strstr"),
        load_options={"auto_load_libs": True},
        exclude_sim_procedures_list=["strstr"],
    )
    simgr = p.factory.simulation_manager()
    simgr.explore(find=[0x4005FB])
    s = simgr.found[0]
    assert s.solver.eval(s.memory.load(s.regs.rax, 9), cast_to=bytes) == b"hi there\0"


def strtol():
    p = angr.Project(os.path.join(test_location, "x86_64", "strtol_test"), auto_load_libs=True)
    state = p.factory.entry_state(remove_options={angr.options.LAZY_SOLVES})
    simgr = p.factory.simulation_manager(thing=state)
    simgr.explore(find=0x400804, num_find=10)
    assert len(simgr.found) == 10


def veritesting():
    p = angr.Project(
        os.path.join(test_location, "x86_64", "veritesting_a"),
        load_options={"auto_load_libs": False},
        use_sim_procedures=True,
    )
    simgr = p.factory.simulation_manager(veritesting=True)
    simgr.explore(find=0x400674)
    assert len(simgr.found) == 1


def _libc_func(name):
    from angr.procedures.definitions import SIM_LIBRARIES

    return lambda state, arguments: (
        SIM_LIBRARIES["libc.so.6"][0].get(name, "AMD64").execute(state, arguments=arguments).ret_expr
    )


def libc_strings(reps=5):
    strlen = _libc_func("strlen")
    strncmp = _libc_func("strncmp")
    strstr_ = _libc_func("strstr")

    for _ in range(reps):
        # symbolic left, symbolic right, symbolic length
        s = angr.SimState(arch="AMD64", mode="symbolic")
        maxlen = claripy.BVS("len", 64)
        s.memory.store(0x1000, claripy.BVS("left", 32))
        s.memory.store(0x2000, claripy.BVS("right", 32))
        s.add_constraints(strlen(s, arguments=[claripy.BVV(0x1000, 64)]) == 3)
        s.add_constraints(strlen(s, arguments=[claripy.BVV(0x2000, 64)]) == 0)
        s.add_constraints(maxlen != 0)
        c = strncmp(s, arguments=[claripy.BVV(0x1000, 64), claripy.BVV(0x2000, 64), maxlen])
        s_match = s.copy()
        s_match.add_constraints(c == 0)
        assert not s_match.satisfiable()

        # symbolic haystack, concrete needle
        s2 = angr.SimState(arch="AMD64", mode="symbolic")
        haystack = claripy.BVS("haystack", 8 * 16)
        s2.memory.store(0x10, haystack)
        s2.memory.store(0xB0, claripy.BVV(b"AB\0"))
        s2.add_constraints(strstr_(s2, arguments=[claripy.BVV(0x10, 64), claripy.BVV(0xB0, 64)]) != 0)
        assert s2.satisfiable()
        s2.solver.eval_upto(haystack, 2)


def tight_loops():
    p = angr.Project(os.path.join(test_location, "x86_64", "perf_tight_loops"), auto_load_libs=False)
    state = p.factory.full_init_state(remove_options={angr.options.UNICORN})
    p.factory.simgr(state).explore()


def state_copy(reps=4000):
    bvs = claripy.BVS("foo", 8)
    state = angr.Project(
        os.path.join(test_location, "x86_64", "fauxware"), main_opts={"base_addr": 0x400000}, auto_load_libs=True
    ).factory.full_init_state(add_options={angr.options.REVERSE_MEMORY_NAME_MAP})
    for _ in range(reps):
        state = state.copy()
        state.memory.store(0x400000, bvs)


SCENARIOS = {
    "fauxware": fauxware,
    "fauxware_armel": fauxware_armel,
    "strstr": strstr,
    "strtol": strtol,
    "veritesting": veritesting,
    "libc_strings": libc_strings,
    "tight_loops": tight_loops,
    "state_copy": state_copy,
}


#
# reporting
#


def component_of(filename: str) -> str:
    """Map a source file to the subsystem it belongs to, for self-time rollups."""
    if os.sep + "z3" + os.sep in filename:
        return "z3 (native solver)"
    if os.sep + "claripy" + os.sep in filename:
        if f"{os.sep}ast" in filename or "operations" in filename:
            return "claripy AST construction"
        if f"{os.sep}backends" in filename:
            return "claripy backend/conversion"
        if f"{os.sep}frontend" in filename or "algorithm" in filename or "simplifications" in filename:
            return "claripy frontend/simplify/replace"
        return "claripy other"
    if f"angr{os.sep}storage{os.sep}" in filename:
        return "angr memory (mixins+pages)"
    if f"angr{os.sep}engines{os.sep}" in filename:
        return "angr engines (VEX/SimProcedure)"
    if f"angr{os.sep}state_plugins{os.sep}" in filename or f"angr{os.sep}sim_state" in filename:
        return "angr state/plugins"
    if f"angr{os.sep}" in filename:
        return "angr other"
    if os.sep + "pyvex" + os.sep in filename:
        return "pyvex (lifting)"
    if os.sep + "cle" + os.sep in filename or "elftools" in filename:
        return "cle/loader"
    if filename == "~" or filename.startswith("<"):
        return "builtins/interpreter"
    return "python stdlib/other"


def report(path: str, top: int = 20) -> None:
    stats = pstats.Stats(path)
    total = stats.total_tt or 1.0

    rollup: dict[str, float] = defaultdict(float)
    rows = []
    for (filename, lineno, name), (_cc, nc, tt, ct, _callers) in stats.stats.items():
        rollup[component_of(filename)] += tt
        rows.append((tt, ct, nc, f"{os.path.basename(filename)}:{lineno}({name})"))

    print(f"\n=== {os.path.basename(path)}: {total:.2f}s, {stats.total_calls} calls ===")
    print("self time by component:")
    for comp, secs in sorted(rollup.items(), key=lambda kv: -kv[1]):
        if secs / total >= 0.005:
            print(f"  {secs:8.2f}s {100 * secs / total:5.1f}%  {comp}")

    print(f"top {top} functions by self time:")
    print(f"  {'self':>8} {'cum':>8} {'ncalls':>10}  function")
    for tt, ct, nc, where in sorted(rows, reverse=True)[:top]:
        print(f"  {tt:8.2f} {ct:8.2f} {nc:10d}  {where}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("outdir", nargs="?", help="directory to write .prof files to")
    parser.add_argument("scenarios", nargs="*", default=None, help=f"subset of: {', '.join(SCENARIOS)}")
    parser.add_argument("--report", metavar="PROF", help="summarize an existing .prof file and exit")
    parser.add_argument("--top", type=int, default=20, help="how many functions to list (default: 20)")
    args = parser.parse_args()

    if args.report:
        report(args.report, args.top)
        return 0

    if not args.outdir:
        parser.error("outdir is required unless --report is given")

    names = args.scenarios or list(SCENARIOS)
    unknown = [n for n in names if n not in SCENARIOS]
    if unknown:
        parser.error(f"unknown scenario(s): {', '.join(unknown)}")

    os.makedirs(args.outdir, exist_ok=True)
    for name in names:
        out = os.path.join(args.outdir, f"{name}.prof")
        profiler = cProfile.Profile()
        start = time.time()
        profiler.enable()
        try:
            SCENARIOS[name]()
        finally:
            profiler.disable()
            profiler.dump_stats(out)
        print(f"{name}: {time.time() - start:.2f}s (profiled) -> {out}", flush=True)
        report(out, args.top)
    return 0


if __name__ == "__main__":
    sys.exit(main())
