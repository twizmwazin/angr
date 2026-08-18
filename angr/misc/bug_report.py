from __future__ import annotations

import ctypes
import datetime
import gc
import importlib
import importlib.metadata
import importlib.util
import os
import sys
import sysconfig
from collections.abc import Callable
from typing import Any

try:
    from git import InvalidGitRepositoryError, Repo

    have_gitpython = True
except ImportError:
    have_gitpython = False
    print("If you install gitpython (`pip install gitpython`), I can give you git info too!")


angr_modules = [
    "angr",
    "archinfo",
    "claripy",
    "cle",
    "pypcode",
    "pyvex",
    "unicorn",
    "z3",
]
# Each entry maps a module name to a function that, given that module, digs out the handle to the
# native library behind it. The module is passed in rather than imported at the top of this file:
# these are exactly the imports most likely to be broken in an environment someone is reporting a
# bug about, so they must not be able to break the report itself.
native_modules: dict[str, Callable[[Any], object]] = {
    "angr": lambda m: m.state_plugins.unicorn_engine._UC_NATIVE,
    "pyvex": lambda m: m.pvc,
    "unicorn": lambda m: m.unicorn_py3.unicorn.uclib,
    "z3": lambda m: next(x for x in gc.get_objects() if type(x) is ctypes.CDLL and "z3" in str(x)),  # YIKES FOREVER
}
python_packages = {"z3": "z3-solver"}


def get_venv():
    if "VIRTUAL_ENV" in os.environ:
        return os.environ["VIRTUAL_ENV"]
    return None


def print_versions():
    for m in angr_modules:
        print(f"######## {m} #########")
        try:
            spec = importlib.util.find_spec(m)
        except ImportError:
            print("Python could not find " + m)
            continue
        except Exception as e:  # pylint: disable=broad-except
            print(f"An error occurred importing {m}: {e}")
            continue
        # find_spec returns None for a module that is not installed, and a spec with origin None
        # for a namespace package -- neither of which has a file to report or a repo to inspect.
        if spec is None or spec.origin is None:
            print("Python could not find " + m)
            continue
        python_filename = spec.origin
        print(f"Python found it in {python_filename}")
        try:
            pip_package = python_packages.get(m, m)
            pip_version = importlib.metadata.version(pip_package)
            print(f"Pip version {pip_version}")
        except Exception:  # pylint: disable-broad-except
            print("Pip version not found!")
        print_git_info(python_filename)


def print_git_info(dirname):
    if not have_gitpython:
        return
    try:
        repo = Repo(dirname, search_parent_directories=True)
    except InvalidGitRepositoryError:
        print("Couldn't find git info")
        return
    cur_commit = repo.commit()
    cur_branch = repo.active_branch
    print("Git info:")
    print(f"\tCurrent commit {cur_commit.hexsha} from branch {cur_branch.name}")
    try:
        # EDG: Git is insane, but this should work 99% of the time
        cur_tb = cur_branch.tracking_branch()
        if cur_tb.is_remote():
            remote_name = cur_tb.remote_name
            remote_url = repo.remotes[remote_name].url
            print(f"\tChecked out from remote {remote_name}: {remote_url}")
        else:
            print(f"Tracking local branch {cur_tb.name}")
    except Exception:  # pylint: disable=broad-except
        print("Could not resolve tracking branch or remote info!")


def print_system_info():
    print("Platform: " + sysconfig.get_platform())
    print("Python version: " + str(sys.version))


def print_native_info():
    print("######### Native Module Info ##########")
    for module, funcs in native_modules.items():
        try:
            imported = importlib.import_module(module)
            try:
                print(f"{module}: {funcs(imported)}")
            except Exception as e:  # pylint: disable=broad-except
                print(f"{module}: imported but path finding raised a {type(e)}: {e}")
        except ModuleNotFoundError:
            print(f"{module}: NOT FOUND")
        except ImportError:
            print(f"{module}: FOUND BUT FAILED TO IMPORT")
        except Exception as e:  # pylint: disable=broad-except
            print(f"{module}: __import__ raised a {type(e)}: {e}")


def bug_report():
    print("angr environment report")
    print("=============================")
    print("Date: " + str(datetime.datetime.today()))
    if get_venv():
        print("Running in virtual environment at " + get_venv())
    else:
        print("!!! running in global environment.  Are you sure? !!!")
    print_system_info()
    print_versions()
    print_native_info()


if __name__ == "__main__":
    bug_report()
