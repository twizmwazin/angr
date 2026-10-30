use clarirs_core::prelude::*;
use num_traits::Signed;

use crate::{reduce::Reduce, strided_interval::ComparisonResult};

/// A solver that uses Value Set Analysis (VSA) for symbolic computation
#[derive(Clone, Debug)]
pub struct VSASolver<'c> {
    ctx: &'c Context<'c>,
}

impl<'c> VSASolver<'c> {
    /// Create a new VSA solver
    pub fn new(ctx: &'c Context<'c>) -> Self {
        Self { ctx }
    }

    /// Enumerate up to `n` values of a single expression from its value set.
    fn eval_one(&self, expr: &AstRef<'c>, n: u32) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        match expr.ast_type() {
            AstType::Bool => expr
                .simplify()?
                .reduce()?
                .into_bool()
                .and_then(|comp_result| match comp_result {
                    ComparisonResult::True => Ok(vec![self.context().boolv(true)?]),
                    ComparisonResult::False => Ok(vec![self.context().boolv(false)?]),
                    ComparisonResult::Maybe => match n {
                        0 => Ok(vec![]),
                        1 => Ok(vec![self.context().boolv(true)?]),
                        _ => Ok(vec![
                            self.context().boolv(true)?,
                            self.context().boolv(false)?,
                        ]),
                    },
                }),
            AstType::BitVec(_) => expr.simplify()?.reduce()?.into_bv().and_then(|si| {
                if si.is_empty() {
                    return Ok(vec![]);
                }
                si.eval(n)
                    .into_iter()
                    .map(|bv| self.context().bvv(BitVec::from((bv, expr.size()))))
                    .collect()
            }),
            AstType::Float(_) | AstType::String => Err(ClarirsError::UnsupportedOperation(
                "Only boolean and bitvector evaluation is supported in VSASolver".to_string(),
            )),
        }
    }
}

/// The first `limit` rows of the cartesian product of `columns`, in
/// lexicographic order of column indices (the last column varies fastest).
/// There are no rows if any column is empty.
fn cartesian_rows<T: Clone>(columns: &[Vec<T>], limit: usize) -> Vec<Vec<T>> {
    if limit == 0 || columns.iter().any(|column| column.is_empty()) {
        return Vec::new();
    }
    let mut rows = Vec::new();
    let mut indices = vec![0usize; columns.len()];
    loop {
        rows.push(
            columns
                .iter()
                .zip(&indices)
                .map(|(column, &i)| column[i].clone())
                .collect(),
        );
        if rows.len() == limit {
            return rows;
        }
        // Advance the odometer; stop once every combination has been emitted.
        let mut pos = columns.len();
        loop {
            if pos == 0 {
                return rows;
            }
            pos -= 1;
            indices[pos] += 1;
            if indices[pos] < columns[pos].len() {
                break;
            }
            indices[pos] = 0;
        }
    }
}

impl<'c> HasContext<'c> for VSASolver<'c> {
    fn context(&self) -> &'c Context<'c> {
        self.ctx
    }
}

impl<'c> Solver<'c> for VSASolver<'c> {
    fn add(&mut self, _: &AstRef<'c>) -> Result<(), ClarirsError> {
        Ok(())
    }

    fn clear(&mut self) -> Result<(), ClarirsError> {
        Ok(())
    }

    fn constraints(&self) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        Ok(vec![])
    }

    fn simplify(&mut self) -> Result<(), ClarirsError> {
        Ok(())
    }

    fn satisfiable(&mut self) -> Result<bool, ClarirsError> {
        Ok(true)
    }

    fn batch_eval_n(
        &mut self,
        exprs: &[AstRef<'c>],
        n: u32,
    ) -> Result<Vec<Vec<AstRef<'c>>>, ClarirsError> {
        if n == 0 {
            return Ok(Vec::new());
        }
        // VSA tracks each expression's value set independently and keeps no
        // relational information between them, so the set of consistent rows
        // is over-approximated by the cartesian product of the per-expression
        // value sets. Each column needs at most `n` values to fill `n` rows.
        let columns = exprs
            .iter()
            .map(|expr| self.eval_one(expr, n))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(cartesian_rows(&columns, n as usize))
    }

    fn is_true(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        Ok(matches!(
            expr.simplify()?.reduce()?.into_bool()?,
            ComparisonResult::True
        ))
    }

    fn is_false(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        Ok(matches!(
            expr.simplify()?.reduce()?.into_bool()?,
            ComparisonResult::False
        ))
    }

    fn has_true(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        Ok(matches!(
            expr.simplify()?.reduce()?.into_bool()?,
            ComparisonResult::True | ComparisonResult::Maybe
        ))
    }

    fn has_false(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        Ok(matches!(
            expr.simplify()?.reduce()?.into_bool()?,
            ComparisonResult::False | ComparisonResult::Maybe
        ))
    }

    fn min_unsigned(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        expr.simplify()?.reduce()?.into_bv().and_then(|si| {
            let (min_bound, _) = si.get_unsigned_bounds();
            expr.context().bvv(BitVec::from((min_bound, expr.size())))
        })
    }

    fn max_unsigned(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        expr.simplify()?.reduce()?.into_bv().and_then(|si| {
            let (_, max_bound) = si.get_unsigned_bounds();
            expr.context().bvv(BitVec::from((max_bound, expr.size())))
        })
    }

    fn min_signed(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        expr.simplify()?.reduce()?.into_bv().and_then(|si| {
            let (min_bound, _) = si.get_signed_bounds();
            // Convert BigInt back to unsigned representation for two's complement
            let unsigned_min = if min_bound.is_negative() {
                let modulus = num_bigint::BigUint::from(1u32) << expr.size();
                let abs_val = (-min_bound.clone()).to_biguint().unwrap();
                &modulus - &abs_val
            } else {
                min_bound.to_biguint().unwrap()
            };
            expr.context()
                .bvv(BitVec::from((unsigned_min, expr.size())))
        })
    }

    fn max_signed(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        expr.simplify()?.reduce()?.into_bv().and_then(|si| {
            let (_, max_bound) = si.get_signed_bounds();
            // Convert BigInt back to unsigned representation for two's complement
            let unsigned_max = if max_bound.is_negative() {
                let modulus = num_bigint::BigUint::from(1u32) << expr.size();
                let abs_val = (-max_bound.clone()).to_biguint().unwrap();
                &modulus - &abs_val
            } else {
                max_bound.to_biguint().unwrap()
            };
            expr.context()
                .bvv(BitVec::from((unsigned_max, expr.size())))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cartesian_rows_enumerates_in_order_and_truncates() {
        let columns = vec![vec![1, 2], vec![10, 20, 30]];
        assert_eq!(
            cartesian_rows(&columns, 10),
            vec![
                vec![1, 10],
                vec![1, 20],
                vec![1, 30],
                vec![2, 10],
                vec![2, 20],
                vec![2, 30]
            ]
        );
        assert_eq!(cartesian_rows(&columns, 4).len(), 4);
        assert!(cartesian_rows(&columns, 0).is_empty());
        // An empty column admits no rows; no columns admit the empty row.
        assert!(cartesian_rows(&[vec![1], vec![]], 3).is_empty());
        assert_eq!(cartesian_rows::<u8>(&[], 3), vec![Vec::<u8>::new()]);
    }

    #[test]
    fn batch_eval_n_combines_value_sets() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut solver = VSASolver::new(&ctx);
        let k = |v: u64| ctx.bvv(BitVec::from((v, 8)));

        // A concrete bitvector has one value, a symbolic boolean two: the
        // rows are their product, each row one value per expression.
        let b = ctx.bools("b")?;
        let rows = solver.batch_eval_n(&[k(7)?, b.clone()], 5)?;
        assert_eq!(
            rows,
            vec![vec![k(7)?, ctx.true_()?], vec![k(7)?, ctx.false_()?]]
        );
        // Truncated to the requested count.
        assert_eq!(solver.batch_eval_n(&[k(7)?, b.clone()], 1)?.len(), 1);
        assert!(solver.batch_eval_n(std::slice::from_ref(&b), 0)?.is_empty());

        // The single-expression entry points go through the same path.
        assert_eq!(solver.eval_n(&b, 5)?.len(), 2);
        assert_eq!(solver.eval(&k(7)?)?, k(7)?);
        Ok(())
    }
}
