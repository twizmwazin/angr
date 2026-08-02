//! Points this extension at the `libz3` that ships in the `z3-solver` wheel, a build and runtime
//! dependency of angr, so that it links against the very library the Python environment carries.
//!
//! Windows is left alone: it links against an import library that clarirs-z3 pulls from Z3's own
//! release, and resolves the DLL out of the wheel at runtime instead. Nothing is emitted either
//! when no wheel is in reach — a bare `cargo build`/`cargo test` outside a Python environment —
//! which leaves the library to `z3-sys`, whether it comes from pkg-config,
//! `Z3_LIBRARY_PATH_OVERRIDE`, or the `gh-release` feature.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Prints the `lib` directory of the installed `z3` package, or nothing if it is not installed.
/// Deliberately does not import z3, which would load libz3 through ctypes for nothing.
const FIND_Z3_LIB_DIR: &str = r#"
import importlib.util, os, sys

try:
    spec = importlib.util.find_spec("z3")
except ImportError:
    spec = None
locations = list(spec.submodule_search_locations) if spec is not None and spec.submodule_search_locations else []
if locations:
    sys.stdout.write(os.path.join(locations[0], "lib"))
"#;

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    for var in ["PYO3_PYTHON", "PYTHON_SYS_EXECUTABLE", "VIRTUAL_ENV"] {
        println!("cargo::rerun-if-env-changed={var}");
    }

    let target_os = env::var("CARGO_CFG_TARGET_OS").expect("CARGO_CFG_TARGET_OS is set by cargo");
    if target_os == "windows" {
        return;
    }
    let Some(lib_dir) = z3_wheel_lib_dir(&target_os) else {
        return;
    };
    println!("cargo::rustc-link-search=native={}", lib_dir.display());

    // ELF only: Mach-O records libz3's bare `libz3.dylib` install name, which rpath entries cannot
    // resolve. There, angr/__init__.py loads the library out of the installed z3 package before
    // importing this extension.
    if matches!(
        target_os.as_str(),
        "linux" | "freebsd" | "netbsd" | "openbsd"
    ) {
        // Installed layout: site-packages/angr/ alongside site-packages/z3/lib/.
        println!("cargo::rustc-link-arg=-Wl,-rpath,$ORIGIN/../z3/lib");
        // Build-time location, which an in-place build and `cargo test` resolve against.
        println!("cargo::rustc-link-arg=-Wl,-rpath,{}", lib_dir.display());
    }
}

fn z3_wheel_lib_dir(target_os: &str) -> Option<PathBuf> {
    python_interpreters()
        .filter_map(|python| ask_for_z3_lib_dir(&python))
        .find(|dir| has_z3_library(dir, target_os))
}

/// Interpreters to ask for the `z3` package, most specific first. setuptools-rust sets
/// `PYO3_PYTHON` to the interpreter being built for, which under build isolation is the ephemeral
/// build environment rather than anything on `PATH`.
fn python_interpreters() -> impl Iterator<Item = PathBuf> {
    let explicit = ["PYO3_PYTHON", "PYTHON_SYS_EXECUTABLE"]
        .into_iter()
        .filter_map(|var| env::var_os(var).map(PathBuf::from));
    let virtualenv = env::var_os("VIRTUAL_ENV").map(|venv| {
        let root = PathBuf::from(venv);
        if cfg!(windows) {
            root.join("Scripts").join("python.exe")
        } else {
            root.join("bin").join("python3")
        }
    });

    explicit
        .chain(virtualenv)
        .chain(["python3", "python"].map(PathBuf::from))
}

fn ask_for_z3_lib_dir(python: &Path) -> Option<PathBuf> {
    let output = Command::new(python)
        .arg("-c")
        .arg(FIND_Z3_LIB_DIR)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let path = String::from_utf8(output.stdout).ok()?;
    let path = path.trim();
    if path.is_empty() {
        None
    } else {
        Some(PathBuf::from(path))
    }
}

fn has_z3_library(dir: &Path, target_os: &str) -> bool {
    let library = if matches!(target_os, "macos" | "ios") {
        "libz3.dylib"
    } else {
        "libz3.so"
    };
    dir.join(library).is_file()
}
