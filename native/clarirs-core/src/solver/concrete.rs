use crate::prelude::*;

/// A concrete solver. This solver is used to evaluate expressions in a concrete
/// context. It does not support adding constraints. It is a glorified
/// simplifier.
#[derive(Clone, Debug)]
pub struct ConcreteSolver {
    ctx: Arc<Context>,
}

impl HasContext for ConcreteSolver {
    fn context(&self) -> Arc<Context> {
        self.ctx.clone()
    }
}

impl ConcreteSolver {
    pub fn new(ctx: Arc<Context>) -> Self {
        Self { ctx }
    }
}

impl Solver for ConcreteSolver {
    fn add(&mut self, _: &AstRef) -> Result<(), ClarirsError> {
        Ok(())
    }

    fn clear(&mut self) -> Result<(), ClarirsError> {
        Ok(())
    }

    fn constraints(&self) -> Result<Vec<AstRef>, ClarirsError> {
        Ok(Vec::new())
    }

    fn simplify(&mut self) -> Result<(), ClarirsError> {
        // ConcreteSolver has no constraints to simplify
        Ok(())
    }

    fn satisfiable(&mut self) -> Result<bool, ClarirsError> {
        Ok(true)
    }

    fn is_true(&mut self, expr: &AstRef) -> Result<bool, ClarirsError> {
        Ok(expr.simplify()?.is_true())
    }

    fn is_false(&mut self, expr: &AstRef) -> Result<bool, ClarirsError> {
        Ok(expr.simplify()?.is_false())
    }

    fn has_true(&mut self, expr: &AstRef) -> Result<bool, ClarirsError> {
        Ok(expr.simplify()?.is_true())
    }

    fn has_false(&mut self, expr: &AstRef) -> Result<bool, ClarirsError> {
        Ok(expr.simplify()?.is_false())
    }

    fn min_unsigned(&mut self, expr: &AstRef) -> Result<AstRef, ClarirsError> {
        self.eval(expr)
    }

    fn max_unsigned(&mut self, expr: &AstRef) -> Result<AstRef, ClarirsError> {
        self.eval(expr)
    }

    fn min_signed(&mut self, expr: &AstRef) -> Result<AstRef, ClarirsError> {
        self.eval(expr)
    }

    fn max_signed(&mut self, expr: &AstRef) -> Result<AstRef, ClarirsError> {
        self.eval(expr)
    }

    fn eval_n(&mut self, expr: &AstRef, n: u32) -> Result<Vec<AstRef>, ClarirsError> {
        if n == 0 {
            return Ok(Vec::new());
        }
        if expr.symbolic() {
            return Err(ClarirsError::UnsupportedOperation(
                "Concrete solver does not support symbolic expressions".to_string(),
            ));
        }
        Ok(vec![expr.simplify_ext(false, true)?])
    }
}

#[cfg(test)]
mod tests {
    use crate::ast::AstFactory;
    use crate::prelude::*;

    #[test]
    fn test_concrete_solver() -> Result<(), ClarirsError> {
        let context = Arc::new(Context::new());
        let mut solver = ConcreteSolver::new(context.clone());

        // Bool tests
        solver.eval(&context.true_()?)?;
        solver.eval(&context.false_()?)?;
        assert!(solver.eval(&context.bools("test")?).is_err());

        // BV tests
        assert!(
            solver.eval(&context.add(
                &context.bvv(BitVec::from((1, 8)))?,
                &context.bvv(BitVec::from((1, 8)))?
            )?)? == context.bvv(BitVec::from((2, 8)))?
        );
        assert!(solver.eval(&context.bvs("test", 8)?).is_err());

        Ok(())
    }
}
