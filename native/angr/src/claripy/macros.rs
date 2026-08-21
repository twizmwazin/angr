#[macro_export]
macro_rules! add_pyfunctions {
    ($m:ident, $($fn_name:path),*,) => {
        $(
            $m.add_function(wrap_pyfunction!($fn_name, $m)?)?;
        )*
    };
}

/// One argument of a [`py_new_op_table!`] entry.
///
/// `T[i]` borrows the inner AST out of `args[i]`, which must be an instance of
/// the `T` pyclass; `rm[i]` extracts a rounding mode out of `args[i]`.
macro_rules! py_new_arg {
    ($py:ident, $args:ident, rm[$idx:literal]) => {
        <PyRM as Into<FPRM>>::into($args[$idx].extract::<PyRM>($py)?)
    };
    ($py:ident, $args:ident, $ty:ident[$idx:literal]) => {
        &$args[$idx].cast_bound::<$ty>($py)?.get().inner
    };
}

/// The op-string table used by an AST class's `#[new]` to rebuild a node from
/// `(op, args)`.
///
/// Each entry names the context method an op maps onto and where in `args` its
/// operands live, e.g. `"__add__" => add(BV[0], BV[1])`. Ops needing anything
/// more (reordered arguments, non-AST arguments, varargs, ...) stay hand-written
/// in the `match` this table is the fallback arm of, and an op in neither place
/// raises `InvalidOperation` just as before.
///
/// `#[new]` reconstructs a node verbatim (it is what unpickling calls), so no
/// entry here simplifies its result.
macro_rules! py_new_op_table {
    (
        $py:ident, $args:ident, $op:ident;
        $($($opstr:literal)|+ => $method:ident($($arg:tt[$idx:literal]),* $(,)?)),* $(,)?
    ) => {
        match $op {
            $(
                $($opstr)|+ => GLOBAL_CONTEXT.$method($(py_new_arg!($py, $args, $arg[$idx])),*)?,
            )*
            _ => return Err(ClaripyError::InvalidOperation($op.to_string())),
        }
    };
}

/// Body of a BV method: `<op>(self, ..)`, simplified the way BV ops are.
macro_rules! bv_op {
    ($self:ident, $py:ident, $method:ident $(, $arg:expr)* $(,)?) => {
        BV::new(
            $py,
            &GLOBAL_CONTEXT
                .$method(&$self.inner $(, $arg)*)?
                .simplify_ext(true, true)?,
        )
    };
}

/// Body of a binary BV method: `self <op> other`, with `other` coerced to
/// `self`'s width.
macro_rules! bv_binop {
    ($self:ident, $py:ident, $other:ident, $method:ident) => {
        bv_op!(
            $self,
            $py,
            $method,
            &$other.unpack_like($py, $self)?.get().inner
        )
    };
}

/// Body of a reflected binary BV method: `other <op> self`.
macro_rules! bv_rbinop {
    ($self:ident, $py:ident, $other:ident, $method:ident) => {
        BV::new(
            $py,
            &GLOBAL_CONTEXT
                .$method(&$other.unpack_like($py, $self)?.get().inner, &$self.inner)?
                .simplify_ext(true, true)?,
        )
    };
}

/// Body of a comparison method: `self <cmp> other` -> `Bool`, with `other`
/// coerced to match `self` (`CoerceBV`/`CoerceFP`).
macro_rules! cmp_op {
    ($self:ident, $py:ident, $other:ident, $method:ident) => {
        Bool::new(
            $py,
            &GLOBAL_CONTEXT
                .$method(&$self.inner, &$other.unpack_like($py, $self)?.get().inner)?
                .simplify()?,
        )
    };
}

/// Body of an FP method: `<op>(self, ..)`.
macro_rules! fp_op {
    ($self:ident, $py:ident, $method:ident $(, $arg:expr)* $(,)?) => {
        FP::new(
            $py,
            &GLOBAL_CONTEXT.$method(&$self.inner $(, $arg)*)?.simplify()?,
        )
    };
}

/// Body of a binary FP method: `self <op> other`, rounded with the default
/// rounding mode.
macro_rules! fp_binop {
    ($self:ident, $py:ident, $other:ident, $method:ident) => {
        fp_op!(
            $self,
            $py,
            $method,
            &$other.unpack_like($py, $self)?.get().inner,
            PyRM::default(),
        )
    };
}

/// Body of a binary Bool method: `self <op> other`.
macro_rules! bool_binop {
    ($self:ident, $py:ident, $other:ident, $method:ident) => {
        Bool::new(
            $py,
            &GLOBAL_CONTEXT
                .$method(&$self.inner, <CoerceBool as Into<AstRef>>::into($other))?
                .simplify()?,
        )
    };
}

/// Body of a binary String method: `self <op> other` -> `$ret`.
macro_rules! str_binop {
    ($ret:ident, $self:ident, $py:ident, $other:ident, $method:ident) => {
        <$ret>::new(
            $py,
            &GLOBAL_CONTEXT
                .$method(&$self.inner, &$other.get().inner)?
                .simplify()?,
        )
    };
}
