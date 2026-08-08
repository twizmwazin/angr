# pylint: disable=missing-class-docstring
from __future__ import annotations

import glob
import importlib
import importlib.resources
import os
import shutil
import subprocess
import sys

from setuptools import Command, setup
from setuptools.command.build import build as st_build
from setuptools.errors import LibError

# Import setuptools_rust to ensure an error is raised if not installed
try:
    _ = importlib.import_module("setuptools_rust")
except ImportError as err:
    raise Exception("angr requires setuptools-rust to build") from err

if sys.platform == "darwin":
    library_file = "unicornlib.dylib"
elif sys.platform in ("win32", "cygwin"):
    library_file = "unicornlib.dll"
else:
    library_file = "unicornlib.so"


class build_protos(Command):
    """Generate the angr/protos/*_pb2.py modules from the *.proto definitions.

    Implements the setuptools.command.build.SubCommand protocol, so it runs as
    part of ``build`` and of PEP 660 editable installs. The modules are always
    generated in the source tree (they must live there for editable installs);
    ``build_py`` then copies them into ``build_lib`` for regular builds.
    """

    description = "generate python modules from protobuf definitions"
    user_options = []

    def initialize_options(self):
        self.build_lib = None
        self.editable_mode = False

    def finalize_options(self):
        self.set_undefined_options("build_py", ("build_lib", "build_lib"))

    def run(self):
        self.execute(self._gen_protos, (), msg="Generating protobuf modules")

    def _gen_protos(self):
        cmd = [sys.executable, "-m", "grpc_tools.protoc", "-I.", "--python_out=.", *self._proto_files()]
        try:
            subprocess.run(cmd, check=True)
        except (FileNotFoundError, subprocess.CalledProcessError) as err:
            raise LibError("Error while generating protobuf modules: " + str(err)) from err

    @staticmethod
    def _proto_files() -> list[str]:
        return sorted(glob.glob("angr/protos/*.proto"))

    def _pb2_files(self) -> list[str]:
        return [proto.removesuffix(".proto") + "_pb2.py" for proto in self._proto_files()]

    def get_source_files(self) -> list[str]:
        return self._proto_files()

    def get_outputs(self) -> list[str]:
        return list(self.get_output_mapping())

    def get_output_mapping(self) -> dict[str, str]:
        return {os.path.join(self.build_lib, pb2): pb2 for pb2 in self._pb2_files()}


class build_unicornlib(Command):
    """Build the unicornlib native library and place it in the angr package.

    Implements the setuptools.command.build.SubCommand protocol, so it runs as
    part of ``build`` and of PEP 660 editable installs. The library is always
    copied into the source tree (it must live there for editable installs);
    ``build_py`` then copies it into ``build_lib`` as package data for regular
    builds.
    """

    description = "build the unicornlib native library"
    user_options = []

    def initialize_options(self):
        self.build_lib = None
        self.editable_mode = False

    def finalize_options(self):
        self.set_undefined_options("build_ext", ("build_lib", "build_lib"))

    def run(self):
        self.execute(self._build_unicornlib, (), msg="Building unicornlib")

    @staticmethod
    def _build_unicornlib():
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

        shutil.copy(os.path.join("native/unicornlib", library_file), "angr")

    def get_source_files(self) -> list[str]:
        return sorted(f for f in glob.glob("native/unicornlib/**/*", recursive=True) if os.path.isfile(f))

    def get_outputs(self) -> list[str]:
        return list(self.get_output_mapping())

    def get_output_mapping(self) -> dict[str, str]:
        return {os.path.join(self.build_lib, "angr", library_file): os.path.join("angr", library_file)}


class clean_unicornlib(Command):
    description = "remove unicornlib build artifacts"
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        self.execute(self._clean_unicornlib, (), msg="Cleaning unicornlib")

    @staticmethod
    def _clean_unicornlib():
        for pattern in ("*.o", "*.obj", "*.so", "*.dll", "*.dylib"):
            for fname in glob.glob(os.path.join("native", "unicornlib", pattern)):
                os.unlink(fname)


class build(st_build):
    sub_commands = [("build_protos", None), ("build_unicornlib", None), *st_build.sub_commands]


setup(
    cmdclass={
        "build": build,
        "build_protos": build_protos,
        "build_unicornlib": build_unicornlib,
        "clean_unicornlib": clean_unicornlib,
    }
)
