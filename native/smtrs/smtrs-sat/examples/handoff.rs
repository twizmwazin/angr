//! Replay a DIMACS file through `SatBackend` and time *only* the handoff.
//!
//! `t_blast` in `--stats-json` covers the AIG traversal and the CNF handoff
//! together, so it cannot say which of the two a change moved. This drives the
//! receiving side alone — `new_var` and `add_clause`, in the order and with the
//! interleaving `Aig::emit` produces (a variable is allocated just before the
//! clauses that define it, so allocating on first mention reproduces it) — and
//! nothing else. Solving is deliberately not called.
//!
//! Usage: `cargo run --release --example handoff -- FILE.cnf [REPEATS]`,
//! against a file written by `SMTRS_DUMP_CNF=1`.

use smtrs_sat::{Backend, CdclBackend, Lit, SatBackend};

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("usage: handoff FILE.cnf [REPEATS]");
    let repeats: usize = args.next().map_or(5, |s| s.parse().expect("REPEATS"));

    // Parse once, outside the timed region: the point is the backend, not the
    // reader. Clauses are kept flat with an index so the replay walks memory
    // the way the emitter hands them over.
    let text = std::fs::read_to_string(&path).expect("read cnf");
    let mut lits: Vec<i32> = Vec::new();
    let mut ends: Vec<usize> = Vec::new();
    for line in text.lines() {
        if line.starts_with('c') || line.starts_with('p') || line.trim().is_empty() {
            continue;
        }
        for tok in line.split_ascii_whitespace() {
            let v: i32 = tok.parse().expect("dimacs literal");
            if v == 0 {
                ends.push(lits.len());
            } else {
                lits.push(v);
            }
        }
    }
    if ends.last() != Some(&lits.len()) {
        ends.push(lits.len());
    }
    let max_var = lits.iter().map(|v| v.unsigned_abs()).max().unwrap_or(0);
    eprintln!(
        "{}: {} clauses, {} literals, {} variables",
        path,
        ends.len(),
        lits.len(),
        max_var
    );

    // `SMTRS_HANDOFF_DIRECT=1` replays into `CdclBackend` rather than the
    // `Backend` enum, which is how much the runtime backend selection costs on
    // this path. `Aig::emit` is generic over `SatBackend`, so the enum's arm
    // choice is a predictable branch rather than a virtual call — the pair of
    // numbers is what says whether that is true in practice.
    let direct = std::env::var_os("SMTRS_HANDOFF_DIRECT").is_some();
    let best = if direct {
        replay::<CdclBackend>(&lits, &ends, repeats, CdclBackend::new)
    } else {
        replay::<Backend>(&lits, &ends, repeats, Backend::from_env)
    };
    println!(
        "best {:.4} s   {:.1} ns/clause   {:.1} ns/literal{}",
        best,
        best * 1e9 / ends.len() as f64,
        best * 1e9 / lits.len() as f64,
        if direct { "   [direct]" } else { "" }
    );
}

fn replay<B: SatBackend>(lits: &[i32], ends: &[usize], repeats: usize, make: fn() -> B) -> f64 {
    let mut best = f64::INFINITY;
    for _ in 0..repeats {
        let t = std::time::Instant::now();
        let mut sat = make();
        let mut allocated: u32 = 0;
        let mut buf: Vec<Lit> = Vec::new();
        let mut start = 0usize;
        for &end in ends {
            let clause = &lits[start..end];
            start = end;
            // Allocate on first mention, as the emitter does.
            let need = clause.iter().map(|v| v.unsigned_abs()).max().unwrap_or(0);
            while allocated < need {
                sat.new_var();
                allocated += 1;
            }
            buf.clear();
            buf.extend(
                clause
                    .iter()
                    .map(|&v| Lit::from_index(v.unsigned_abs() - 1, v > 0)),
            );
            sat.add_clause(&buf);
        }
        let secs = t.elapsed().as_secs_f64();
        best = best.min(secs);
        // Keep the backend alive to here so teardown is not timed away.
        std::hint::black_box(sat.num_vars());
    }
    best
}
