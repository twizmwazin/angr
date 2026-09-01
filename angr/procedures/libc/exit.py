from __future__ import annotations

import angr


class exit(angr.SimProcedure):  # pylint:disable=redefined-builtin  # noqa: A001
    # pylint:disable=arguments-differ

    NO_RET = True

    def run(self, exit_code):
        self.exit(exit_code)
