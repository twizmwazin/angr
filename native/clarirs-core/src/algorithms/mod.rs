pub mod canonicalize;
pub mod collect_vars;
pub mod excavate_ite;
pub mod find_variable;
pub mod post_order;
pub mod pre_order;
pub mod reconstruct;
pub mod replace;
pub mod simplify;
pub mod walk;

pub use canonicalize::{canonicalize, structurally_match};
pub use post_order::walk_post_order;
pub use pre_order::walk_pre_order;
pub use walk::walk;
