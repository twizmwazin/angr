"""Temporary: locate the MSVC ICE in VEX. Run from a pyvex checkout root."""
import concurrent.futures, os, re, subprocess, sys

BASE = ["cl", "/nologo", "/c", "/DNDEBUG", "/MD", "/DAVX_512", "/DPYVEX", "/DWIN32", "/D_WINDOWS",
        "/Ivex/pub", "/Ivex/priv", "/Ipyvex/include", "/Ipyvex_c", "/W1"]
O2 = ["/O2", "/Ob2"]
os.makedirs("obj", exist_ok=True)


def compile_(src, opts, tag=""):
    obj = os.path.join("obj", re.sub(r"\W", "_", src + tag) + ".obj")
    p = subprocess.run(BASE + opts + ["/Fo" + obj, src], capture_output=True, text=True, errors="replace")
    out = p.stdout + p.stderr
    if p.returncode == 0:
        return "ok", out
    if "bad size" in out or "C1001" in out or "RaiseException" in out or p.returncode not in (1, 2):
        return "ICE", out
    return "err", out


srcs = [l.strip() for l in open("srcs.txt") if l.strip()]
with concurrent.futures.ThreadPoolExecutor(4) as ex:
    res = list(ex.map(lambda s: compile_(s, O2), srcs))
bad = []
for s, (st, out) in zip(srcs, res):
    print(f"[{st}] {s}", flush=True)
    if st != "ok":
        bad.append(s)
        print("\n".join(l for l in out.splitlines() if "C4005" not in l and "previous definition" not in l)[-3000:])

VARIANTS = {
    "O1": ["/O1"], "Od": ["/Od"], "O2_Ob1": ["/O2", "/Ob1"], "O2_Ob0": ["/O2", "/Ob0"],
    "Ox": ["/Ox"], "O2_noSSA": O2 + ["/d2SSAOptimizer-"], "Og_only": ["/Og"],
    "O2_Oy-": O2 + ["/Oy-"], "O2_Oi-": O2 + ["/Oi-"], "Os": ["/Os", "/Og"], "Ot": ["/Ot", "/Og"],
    "O2_GL": O2 + ["/GL"], "O2_std17": O2 + ["/std:c17"], "O2_arch_AVX2": O2 + ["/arch:AVX2"],
}

for src in bad:
    print(f"\n===== variants for {src}", flush=True)
    for name, opts in VARIANTS.items():
        print(f"  {name}: {compile_(src, opts, name)[0]}", flush=True)

    lines = open(src, encoding="latin-1").read().split("\n")
    braces = [i for i, l in enumerate(lines) if re.match(r"^\}\s*;?\s*$", l)]
    n = len(braces)  # segment i ends at braces[i]
    culprits = []

    def test(k):
        """optimise segments [0,k) except culprits; everything else unoptimised"""
        state = [(i < k and i not in culprits) for i in range(n)]
        out, cur, seg = [], True, 0
        if not state[0]:
            out.append('#pragma optimize("", off)'); cur = False
        for i, l in enumerate(lines):
            out.append(l)
            if seg < n and i == braces[seg]:
                seg += 1
                want = state[seg] if seg < n else True
                if want != cur:
                    out.append('#pragma optimize("", %s)' % ("on" if want else "off")); cur = want
        tmp = src[:-2] + "__bisect.c"
        open(tmp, "w", encoding="latin-1").write("\n".join(out))
        st, o = compile_(tmp, O2)
        if st == "err":
            print(o[-3000:]); sys.exit("unexpected compile error during bisect")
        return st

    print(f"  bisecting over {n} segments", flush=True)
    for _ in range(8):
        if test(n) == "ok":
            break
        lo, hi = 0, n  # test(lo) ok, test(hi) ICE
        while hi - lo > 1:
            mid = (lo + hi) // 2
            if test(mid) == "ICE":
                hi = mid
            else:
                lo = mid
        c = hi - 1
        culprits.append(c)
        a = braces[c - 1] + 1 if c else 0
        b = braces[c]
        print(f"  CULPRIT segment {c}: {src} lines {a+1}-{b+1}", flush=True)
        print("\n".join(lines[a:b + 1][:60]), flush=True)
    print(f"  culprits for {src}: {culprits}; clean with those unoptimised: {test(n)}", flush=True)
print("BAD FILES:", bad)
