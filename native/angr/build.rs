//! Generates the body of `src/ailment/vexop_names.rs`: the VEX `IROp` enum
//! names, in enum order, for `IROP_NAMES[op_int - IOP_BASE]` lookups.
//!
//! This is pure VEX-ISA data, so the source of truth is libVEX itself, read
//! through pyvex's `irop_enums_to_ints` (pyvex builds it from the real headers
//! via cffi). pyvex is a build requirement of the wheel, so the table always
//! matches the libVEX the extension is loaded next to; building this crate
//! needs an interpreter that can `import pyvex`.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::env;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// Value of `Iop_INVALID`, the base of the (contiguous) `IROp` enum. Ops are
/// looked up by subtracting it, so the dump is checked against it rather than
/// trusted to keep starting there.
const IOP_BASE: u32 = 0x1400;

/// Range markers, not real ops. They share an integer with a neighbouring real
/// member (`Iop_FIRST_EVEX` aliases `Iop_LAST_NOT_EVEX`), so they must not
/// claim a slot of their own or every later name would be off by one.
const SENTINELS: [&str; 3] = ["Iop_FIRST_EVEX", "Iop_LAST_NOT_EVEX", "Iop_LAST"];

/// Prints where pyvex was imported from and then every `IROp` member as
/// `name value`, one per line. Both come after a marker: importing pyvex pulls
/// in cffi and a shared library, and the interpreter may have a
/// `sitecustomize` of its own, so only what follows the marker is ours.
const DUMP_IROPS: &str = "\
import sys
import pyvex
from pyvex.enums import irop_enums_to_ints
sys.stdout.write('--- irops ---\\n')
sys.stdout.write('%s\\n' % pyvex.__file__)
for name, value in sorted(irop_enums_to_ints.items()):
    sys.stdout.write('%s %d\\n' % (name, value))
";

/// Start of [`DUMP_IROPS`]' actual output. No newline: Python's text-mode
/// stdout writes CRLF on Windows.
const DUMP_MARKER: &str = "--- irops ---";

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-env-changed=PYO3_PYTHON");
    println!("cargo::rerun-if-env-changed=PYTHON_SYS_EXECUTABLE");

    let names = names_from_pyvex();
    check_names(&names);

    let out =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is unset")).join("vexop_names.rs");
    fs::write(&out, render(&names))
        .unwrap_or_else(|e| panic!("cannot write {}: {e}", out.display()));
}

/// The interpreter to ask for the op table: the one driving the build if
/// there is one (setuptools-rust points `PYO3_PYTHON` at it, and that is the
/// environment whose pyvex the extension will be imported next to), else
/// whatever `python` is on `PATH`.
fn python_candidates() -> Vec<OsString> {
    for var in ["PYO3_PYTHON", "PYTHON_SYS_EXECUTABLE"] {
        if let Some(exe) = env::var_os(var).filter(|v| !v.is_empty()) {
            return vec![exe];
        }
    }
    vec![OsString::from("python3"), OsString::from("python")]
}

/// The op names as libVEX has them.
fn names_from_pyvex() -> Vec<String> {
    let candidates = python_candidates();
    let dump = candidates
        .iter()
        .find_map(|py| {
            let out = Command::new(py).arg("-c").arg(DUMP_IROPS).output().ok()?;
            out.status
                .success()
                .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
        })
        .unwrap_or_else(|| {
            panic!(
                "cannot read the VEX IROp enum: none of {candidates:?} could `import pyvex`. \
                 Building this crate needs pyvex (a build requirement of the angr wheel); \
                 install it, or point PYO3_PYTHON at an interpreter that has it."
            )
        });
    names_from_dump(&dump)
}

/// Order the `name value` pairs [`DUMP_IROPS`] printed into enum order,
/// dropping the sentinels and checking the two properties the indexing scheme
/// relies on: the enum starts at [`IOP_BASE`] and has no holes.
fn names_from_dump(dump: &str) -> Vec<String> {
    let (noise, dump) = dump.split_once(DUMP_MARKER).unwrap_or_else(|| {
        panic!(
            "pyvex op dump printed no ops, only {:?}",
            first_chars(dump, 200)
        )
    });
    if !noise.is_empty() {
        println!(
            "cargo::warning=ignoring stray output before the pyvex op dump: {:?}",
            first_chars(noise, 200)
        );
    }

    let mut lines = dump.lines().map(str::trim).filter(|line| !line.is_empty());
    // reinstalling or upgrading pyvex has to regenerate the table
    let pyvex = lines.next().expect("pyvex op dump is empty");
    println!("cargo::rerun-if-changed={pyvex}");

    let mut pairs: Vec<(&str, u32)> = lines
        .map(|line| {
            let (name, value) = line
                .split_once(' ')
                .unwrap_or_else(|| panic!("malformed line in pyvex op dump: {line:?}"));
            let value = value
                .parse()
                .unwrap_or_else(|e| panic!("malformed value in pyvex op dump: {line:?}: {e}"));
            (name, value)
        })
        .collect();
    pairs.sort_unstable();

    let mut by_int: BTreeMap<u32, &str> = BTreeMap::new();
    for (name, value) in pairs {
        match by_int.entry(value) {
            Entry::Vacant(slot) => {
                slot.insert(name);
            }
            // keep the real op name if one of the two is a sentinel
            Entry::Occupied(mut slot) => {
                match (SENTINELS.contains(slot.get()), SENTINELS.contains(&name)) {
                    (true, false) => {
                        slot.insert(name);
                    }
                    (false, false) => panic!(
                        "two real ops share value {value:#x}: {}, {name}",
                        slot.get()
                    ),
                    _ => {}
                }
            }
        }
    }

    let (&lo, _) = by_int.iter().next().expect("pyvex reported no IROps");
    let (&hi, _) = by_int.iter().next_back().expect("pyvex reported no IROps");
    assert!(
        lo == IOP_BASE,
        "unexpected IROp base {lo:#x} (expected {IOP_BASE:#x})"
    );
    let missing: Vec<String> = (lo..=hi)
        .filter(|op| !by_int.contains_key(op))
        .take(8)
        .map(|op| format!("{op:#x}"))
        .collect();
    assert!(
        missing.is_empty(),
        "IROp enum is not contiguous; missing {}",
        missing.join(", ")
    );

    by_int.into_values().map(str::to_owned).collect()
}

/// A prefix of `text`, for diagnostics that should not spill a whole dump.
fn first_chars(text: &str, len: usize) -> String {
    text.chars().take(len).collect()
}

/// The names go into the generated source as string literals, so make sure a
/// mangled dump fails here rather than as a syntax error in `OUT_DIR`.
fn check_names(names: &[String]) {
    assert!(!names.is_empty(), "no IROp names to generate");
    for name in names {
        assert!(
            name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
            "implausible IROp name: {name:?}"
        );
    }
}

fn render(names: &[String]) -> String {
    let mut out = String::from(
        "// @generated by build.rs from the VEX IROp enum -- do not edit.\n\
         \n\
         /// Value of `Iop_INVALID`; the base of the (contiguous) `IROp` enum.\n",
    );
    writeln!(out, "pub const IOP_BASE: u32 = {IOP_BASE:#x};").unwrap();
    out.push_str(
        "\n/// Op names in `IROp` enum order, indexed by `op_int - IOP_BASE`.\n\
         pub static IROP_NAMES: &[&str] = &[\n",
    );
    for name in names {
        writeln!(out, "    \"{name}\",").unwrap();
    }
    out.push_str("];\n");
    out
}
