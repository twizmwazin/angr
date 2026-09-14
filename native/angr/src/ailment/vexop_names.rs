//! Maps a VEX `IROp` integer to its enum name. The enum is contiguous from
//! `IOP_BASE`, so `IROP_NAMES[op_int - IOP_BASE]` is the name.
//!
//! The table is pure VEX-ISA data (not classification logic), emitted at build
//! time by `build.rs` from pyvex's `IROp` enum.

include!(concat!(env!("OUT_DIR"), "/vexop_names.rs"));
