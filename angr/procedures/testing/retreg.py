from __future__ import annotations

import angr


class retreg(angr.SimProcedure):
    def run(self, reg: str | None = None):
        return self.state.registers.load(reg)
        # print self.state.options
