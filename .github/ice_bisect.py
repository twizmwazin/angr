"""Temporary: test candidate fixes for the MSVC ICE. Run from a pyvex checkout root."""
import subprocess
SRC = "vex/priv/guest_s390_toIR.c"
CMD = ["cl", "/nologo", "/c", "/O2", "/Ob2", "/DNDEBUG", "/MD", "/DAVX_512", "/DPYVEX", "/Ivex/pub", "/Ivex/priv",
       "/Ipyvex/include", "/Ipyvex_c", "/W1", "/Fotmp.obj"]
orig = open(SRC, encoding="latin-1", newline="").read()
SIG = "static UInt\ns390_decode_and_irgen(const UChar *bytes, UInt insn_length, DisResult *dres)"
EXSIG = "static void\ns390_irgen_EX(UChar r1, IRTemp addr2)"
assert SIG in orig and EXSIG in orig
variants = {
    "baseline": orig,
    "noinline_decode_and_irgen": orig.replace(SIG, "__declspec(noinline) " + SIG),
    "noinline_irgen_EX": orig.replace(EXSIG, "__declspec(noinline) " + EXSIG),
}
for name, text in variants.items():
    open("vex/priv/guest_s390__v.c", "w", encoding="latin-1", newline="").write(text)
    p = subprocess.run(CMD + ["vex/priv/guest_s390__v.c"], capture_output=True, text=True, errors="replace")
    print(f"VARIANT {name}: rc={p.returncode} {'ICE' if 'bad size' in p.stdout + p.stderr else ''}", flush=True)
