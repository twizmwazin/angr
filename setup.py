# pylint: disable=missing-class-docstring
from __future__ import annotations

import glob
import importlib
import importlib.resources
import os
import shutil
import subprocess
import sys

from distutils.command.build import build as st_build
from setuptools import Command, setup
from setuptools.command.develop import develop as st_develop
from setuptools.errors import LibError

try:
    from setuptools_rust import RustExtension
except ImportError as err:
    raise Exception("angr requires setuptools-rust to build") from err


def z3_feature() -> str:
    """Pick the z3 backend for the Rust extension.

    z3-sys can either compile z3 from source ("vendored") or download a
    prebuilt static library from z3's GitHub releases ("gh-release"). Building
    from source takes long enough to blow through Read the Docs' build
    timeout, so gh-release is used there. ANGR_Z3_BUILD overrides the choice
    everywhere; the gh-release download can be authenticated by setting
    READ_ONLY_GITHUB_TOKEN to avoid anonymous GitHub API rate limits.
    """
    choice = os.environ.get("ANGR_Z3_BUILD")
    if choice is None:
        choice = "gh-release" if os.environ.get("READTHEDOCS") else "vendored"
    if choice not in ("vendored", "gh-release"):
        raise ValueError(f"Invalid ANGR_Z3_BUILD value: {choice!r} (expected 'vendored' or 'gh-release')")
    return f"z3-{choice}"

if sys.platform == "darwin":
    library_file = "unicornlib.dylib"
elif sys.platform in ("win32", "cygwin"):
    library_file = "unicornlib.dll"
else:
    library_file = "unicornlib.so"


def build_unicornlib():
    try:
        importlib.import_module("pyvex")
    except ImportError as e:
        raise LibError("You must install pyvex before building angr") from e

    env = os.environ.copy()
    env_data = (
        ("PYVEX_INCLUDE_PATH", "pyvex", "include"),
        ("PYVEX_LIB_PATH", "pyvex", "lib"),
        ("PYVEX_LIB_FILE", "pyvex", "lib\\pyvex.lib"),
    )
    for var, pkg, fnm in env_data:
        base = importlib.resources.files(pkg)
        for child in fnm.split("\\"):
            base = base.joinpath(child)
        env[var] = str(base)

    if sys.platform == "win32":
        cmd = ["nmake", "/f", "Makefile-win"]
    elif shutil.which("gmake") is not None:
        cmd = ["gmake"]
    else:
        cmd = ["make"]
    try:
        subprocess.run(cmd, cwd="native/unicornlib", env=env, check=True)
    except FileNotFoundError as err:
        raise LibError("Couldn't find " + cmd[0] + " in PATH") from err
    except subprocess.CalledProcessError as err:
        raise LibError("Error while building unicornlib: " + str(err)) from err

    shutil.rmtree("angr/lib", ignore_errors=True)
    os.mkdir("angr/lib")
    shutil.copy(os.path.join("native/unicornlib", library_file), "angr")


def build_protos():
    proto_files = sorted(glob.glob("angr/protos/*.proto"))
    cmd = [sys.executable, "-m", "grpc_tools.protoc", "-I.", "--python_out=.", *proto_files]
    try:
        subprocess.run(cmd, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError) as err:
        raise LibError("Error while generating protobuf modules: " + str(err)) from err


def clean_unicornlib():
    oglob = glob.glob("native/*.o")
    oglob += glob.glob("native/*.obj")
    oglob += glob.glob("native/*.so")
    oglob += glob.glob("native/*.dll")
    oglob += glob.glob("native/*.dylib")
    for fname in oglob:
        os.unlink(fname)


class build(st_build):
    def run(self, *args):
        self.execute(build_protos, (), msg="Generating protobuf modules")
        self.execute(build_unicornlib, (), msg="Building unicornlib")
        super().run(*args)


class clean(Command):
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        self.execute(clean, (), msg="Cleaning unicornlib")


class develop(st_develop):
    def run(self):
        self.run_command("build")
        super().run()


cmdclass = {
    "build": build,
    "clean_unicornlib": clean,
    "develop": develop,
}


try:
    from setuptools.command.editable_wheel import editable_wheel as st_editable_wheel

    class editable_wheel(st_editable_wheel):
        def run(self):
            self.run_command("build")
            super().run()

    cmdclass["editable_wheel"] = editable_wheel
except ModuleNotFoundError:
    pass


setup(
    cmdclass=cmdclass,
    rust_extensions=[
        RustExtension(
            target="angr.rustylib",
            path="native/angr/Cargo.toml",
            debug=False,
            args=["--no-default-features"],
            features=[z3_feature()],
        )
    ],
)
