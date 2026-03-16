/// Assembler/Disassembler module using SLEIGH from icicle-emu.
///
/// This module provides Python bindings for a SLEIGH-based assembler and
/// disassembler, offering similar functionality to keystone/capstone but
/// using Ghidra's SLEIGH processor specifications.
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use pyo3::{
    exceptions::{PyRuntimeError, PyValueError},
    prelude::*,
};
use sleigh_runtime::{RuntimeConfig, SleighData, matcher::MatchCase};

/// A single disassembled instruction.
#[pyclass(module = "angr.rustylib.assembler", frozen, from_py_object)]
#[derive(Clone)]
pub struct Instruction {
    /// The address of the instruction.
    #[pyo3(get)]
    pub address: u64,
    /// The size of the instruction in bytes.
    #[pyo3(get)]
    pub size: u32,
    /// The mnemonic of the instruction (e.g., "MOV").
    #[pyo3(get)]
    pub mnemonic: String,
    /// The operand string (e.g., "EAX, 0x1").
    #[pyo3(get)]
    pub op_str: String,
    /// The raw bytes of the instruction.
    #[pyo3(get)]
    pub bytes: Vec<u8>,
}

#[pymethods]
impl Instruction {
    pub fn __repr__(&self) -> String {
        format!(
            "Instruction(0x{:x}: {} {} [{} bytes])",
            self.address, self.mnemonic, self.op_str, self.size
        )
    }

    pub fn __str__(&self) -> String {
        if self.op_str.is_empty() {
            self.mnemonic.clone()
        } else {
            format!("{} {}", self.mnemonic, self.op_str)
        }
    }
}

/// Index mapping mnemonics to constructor IDs for fast lookup during assembly.
struct MnemonicIndex {
    /// Map from lowercase mnemonic -> set of constructor IDs
    by_mnemonic: HashMap<String, Vec<u32>>,
}

impl MnemonicIndex {
    fn build(sleigh: &SleighData) -> Self {
        let mut by_mnemonic: HashMap<String, Vec<u32>> = HashMap::new();

        for (i, constructor) in sleigh.constructors.iter().enumerate() {
            if let Some(str_index) = constructor.mnemonic {
                let mnemonic = sleigh.get_str(str_index).to_lowercase();
                if !mnemonic.is_empty() {
                    by_mnemonic
                        .entry(mnemonic)
                        .or_default()
                        .push(i as u32);
                }
            }
        }

        Self { by_mnemonic }
    }

    fn get_constructors(&self, mnemonic: &str) -> Option<&[u32]> {
        self.by_mnemonic.get(mnemonic).map(|v| v.as_slice())
    }
}

/// Index mapping mnemonics to root matcher case indices.
/// Built at init time by probing each case with a few bit patterns.
struct CaseMnemonicIndex {
    /// Map from lowercase mnemonic -> list of case indices in the root matcher
    by_mnemonic: HashMap<String, Vec<usize>>,
}

impl CaseMnemonicIndex {
    fn build(
        sleigh: &SleighData,
        initial_ctx: u64,
        matcher_cases: &[MatchCase],
        token_size: usize,
    ) -> Self {
        let mut by_mnemonic: HashMap<String, Vec<usize>> = HashMap::new();
        let mut runtime = sleigh_runtime::Runtime::new_with_config(&RuntimeConfig {
            context: initial_ctx,
            ..Default::default()
        });
        let max_bits = (token_size * 8) as u32;

        for (case_idx, case) in matcher_cases.iter().enumerate() {
            let free_positions = free_bit_positions(case.token.mask, max_bits);
            let mut seen_mnemonics: HashSet<String> = HashSet::new();

            // Probe with several bit patterns to discover reachable mnemonics
            let probes: Vec<u64> = {
                let mut p = vec![0u64]; // base bits (all free = 0)
                // All free bits set
                let all_free: u64 = free_positions.iter().fold(0u64, |acc, &pos| acc | (1u64 << pos));
                p.push(all_free);
                // Try each free bit individually (first 8)
                for &pos in free_positions.iter().take(8) {
                    p.push(1u64 << pos);
                }
                // A few more patterns for better coverage
                if free_positions.len() > 1 {
                    p.push(1u64 << free_positions[0] | 1u64 << free_positions[free_positions.len() - 1]);
                }
                p
            };

            for pattern in &probes {
                let mut bits = case.token.bits;
                for (j, &pos) in free_positions.iter().enumerate() {
                    if pattern & (1u64 << j) != 0 {
                        bits |= 1u64 << pos;
                    }
                }

                let mut candidate = bits.to_le_bytes()[..token_size].to_vec();
                candidate.resize(token_size + 16, 0);

                if let Some(inst) = runtime.decode(sleigh, 0, &candidate) {
                    if inst.num_bytes() > 0 {
                        if let Some(disasm) = runtime.disasm(sleigh) {
                            let mnemonic = extract_mnemonic(disasm).to_lowercase();
                            if !mnemonic.is_empty() && seen_mnemonics.insert(mnemonic.clone()) {
                                by_mnemonic.entry(mnemonic).or_default().push(case_idx);
                            }
                        }
                    }
                }
            }
        }

        Self { by_mnemonic }
    }

    fn get_cases(&self, mnemonic: &str) -> Option<&[usize]> {
        self.by_mnemonic.get(mnemonic).map(|v| v.as_slice())
    }
}

/// SLEIGH-based assembler and disassembler.
///
/// Provides assembly and disassembly functionality using SLEIGH processor
/// specifications, supporting all architectures that SLEIGH supports.
#[pyclass(unsendable, module = "angr.rustylib.assembler")]
pub struct SleighAssembler {
    sleigh: SleighData,
    initial_ctx: u64,
    mnemonic_index: MnemonicIndex,
    case_index: CaseMnemonicIndex,
}

/// Extract the mnemonic (first word) from a disassembly string.
fn extract_mnemonic(disasm: &str) -> &str {
    let trimmed = disasm.trim();
    trimmed
        .split(|c: char| c == ' ' || c == '\t')
        .next()
        .unwrap_or(trimmed)
}

/// Normalize a disassembly string for comparison.
/// Lowercases, collapses whitespace, strips trailing whitespace.
fn normalize_asm(s: &str) -> String {
    let lower = s.trim().to_lowercase();
    let mut result = String::with_capacity(lower.len());
    let mut prev_space = false;
    for c in lower.chars() {
        if c.is_whitespace() {
            if !prev_space && !result.is_empty() {
                result.push(' ');
                prev_space = true;
            }
        } else {
            result.push(c);
            prev_space = false;
        }
    }
    if result.ends_with(' ') {
        result.pop();
    }
    result
}

/// Try to decode a byte sequence and check if it matches the target assembly.
/// Returns Some(size) if the decoded disassembly matches the target.
fn try_decode_match(
    runtime: &mut sleigh_runtime::Runtime,
    sleigh: &SleighData,
    bytes: &[u8],
    address: u64,
    target: &str,
) -> Option<usize> {
    let inst = runtime.decode(sleigh, address, bytes)?;
    let size = inst.num_bytes() as usize;
    if size == 0 || size > bytes.len() {
        return None;
    }

    let disasm = runtime.disasm(sleigh)?;
    let normalized = normalize_asm(disasm);
    if normalized == *target {
        Some(size)
    } else {
        None
    }
}

/// Enumerate free bit positions in a mask (bits NOT set in mask).
fn free_bit_positions(mask: u64, max_bits: u32) -> Vec<u32> {
    (0..max_bits)
        .filter(|&i| mask & (1u64 << i) == 0)
        .collect()
}

/// Try assembling using a specific MatchCase by enumerating free bits.
/// Returns the shortest encoding found within the candidate limit.
fn try_assemble_with_case(
    runtime: &mut sleigh_runtime::Runtime,
    sleigh: &SleighData,
    case: &MatchCase,
    token_size: usize,
    address: u64,
    target: &str,
    max_candidates: u64,
) -> Option<Vec<u8>> {
    let base_bits = case.token.bits;
    let mask = case.token.mask;
    let max_bits = (token_size * 8) as u32;
    let free_positions = free_bit_positions(mask, max_bits);
    let num_free = free_positions.len() as u32;
    let total = if num_free >= 64 {
        max_candidates
    } else {
        (1u64 << num_free).min(max_candidates)
    };

    let mut best: Option<Vec<u8>> = None;

    for combo in 0..total {
        let mut bits = base_bits;
        for (j, &pos) in free_positions.iter().enumerate() {
            if combo & (1u64 << j) != 0 {
                bits |= 1u64 << pos;
            }
        }

        let mut candidate = bits.to_le_bytes()[..token_size].to_vec();
        candidate.resize(token_size + 16, 0);

        if let Some(size) = try_decode_match(runtime, sleigh, &candidate, address, target) {
            let result = candidate[..size].to_vec();
            let is_better = match &best {
                None => true,
                Some(prev) => result.len() < prev.len(),
            };
            if is_better {
                if result.len() == 1 {
                    return Some(result);
                }
                best = Some(result);
            }
        }
    }

    best
}

/// Parse numeric operand values from assembly text for smarter encoding.
/// Returns a list of numeric values found in the operands.
fn parse_operand_values(op_str: &str) -> Vec<i64> {
    let mut values = Vec::new();
    for token in op_str.split(|c: char| c == ',' || c == ' ' || c == '\t') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        // Try hex (0x...)
        if let Some(hex) = token.strip_prefix("0x").or_else(|| token.strip_prefix("0X")) {
            if let Ok(v) = u64::from_str_radix(hex, 16) {
                values.push(v as i64);
            }
        } else if let Some(hex) = token.strip_prefix("-0x").or_else(|| token.strip_prefix("-0X"))
        {
            if let Ok(v) = u64::from_str_radix(hex, 16) {
                values.push(-(v as i64));
            }
        } else if let Ok(v) = token.parse::<i64>() {
            values.push(v);
        }
    }
    values
}

/// Try assembling with a case, embedding operand values in the trailing bytes.
/// This handles instructions where immediates extend beyond the token.
fn try_assemble_with_immediates(
    runtime: &mut sleigh_runtime::Runtime,
    sleigh: &SleighData,
    case: &MatchCase,
    token_size: usize,
    address: u64,
    target: &str,
    imm_values: &[i64],
    max_candidates: u64,
) -> Option<Vec<u8>> {
    let base_bits = case.token.bits;
    let mask = case.token.mask;
    let max_bits = (token_size * 8) as u32;
    let free_positions = free_bit_positions(mask, max_bits);
    let num_free = free_positions.len() as u32;
    let total = if num_free >= 64 {
        max_candidates
    } else {
        (1u64 << num_free).min(max_candidates)
    };

    let mut best: Option<Vec<u8>> = None;

    // For each immediate value, try embedding it in different positions after the token
    let imm_bytes_options: Vec<Vec<u8>> = imm_values
        .iter()
        .flat_map(|&v| {
            let uv = v as u64;
            vec![
                // 1 byte LE
                vec![(uv & 0xFF) as u8],
                // 2 bytes LE
                (uv as u16).to_le_bytes().to_vec(),
                // 4 bytes LE
                (uv as u32).to_le_bytes().to_vec(),
                // 8 bytes LE
                uv.to_le_bytes().to_vec(),
                // 2 bytes BE
                (uv as u16).to_be_bytes().to_vec(),
                // 4 bytes BE
                (uv as u32).to_be_bytes().to_vec(),
            ]
        })
        .collect();

    for combo in 0..total {
        let mut bits = base_bits;
        for (j, &pos) in free_positions.iter().enumerate() {
            if combo & (1u64 << j) != 0 {
                bits |= 1u64 << pos;
            }
        }

        let token_bytes: Vec<u8> = bits.to_le_bytes()[..token_size].to_vec();

        // Try with just zeros after token first
        let mut candidate = token_bytes.clone();
        candidate.resize(token_size + 16, 0);
        if let Some(size) =
            try_decode_match(runtime, sleigh, &candidate, address, target)
        {
            let result = candidate[..size].to_vec();
            let is_better = match &best {
                None => true,
                Some(prev) => result.len() < prev.len(),
            };
            if is_better {
                if result.len() == 1 {
                    return Some(result);
                }
                best = Some(result);
            }
        }

        // Try embedding immediate values after the token
        for imm_bytes in &imm_bytes_options {
            let mut candidate = token_bytes.clone();
            candidate.extend_from_slice(imm_bytes);
            candidate.resize(token_size + 16, 0);
            if let Some(size) =
                try_decode_match(runtime, sleigh, &candidate, address, target)
            {
                let result = candidate[..size].to_vec();
                let is_better = match &best {
                    None => true,
                    Some(prev) => result.len() < prev.len(),
                };
                if is_better {
                    if result.len() <= token_size {
                        return Some(result);
                    }
                    best = Some(result);
                }
            }
        }
    }

    best
}

#[pymethods]
impl SleighAssembler {
    /// Create a new SleighAssembler for the given architecture.
    ///
    /// :param architecture: The icicle architecture string (e.g., "x86_64", "armv7a", "mips").
    /// :param processors_path: Path to the SLEIGH processors directory (from pypcode).
    #[new]
    pub fn new(architecture: String, processors_path: String) -> PyResult<Self> {
        let triple: target_lexicon::Triple =
            format!("{architecture}-none").parse().map_err(|e| {
                PyRuntimeError::new_err(format!("Invalid architecture '{architecture}': {e}"))
            })?;

        let (ldef, lang_id) = resolve_sleigh_spec(&triple).ok_or_else(|| {
            PyRuntimeError::new_err(format!("Unsupported architecture: {architecture}"))
        })?;

        let ldef_path = PathBuf::from(&processors_path).join(ldef);
        let lang = sleigh_compile::SleighLanguageBuilder::new(&ldef_path, lang_id)
            .build()
            .map_err(|e| {
                PyRuntimeError::new_err(format!(
                    "Failed to initialize SLEIGH for {architecture}: {e}"
                ))
            })?;

        let mnemonic_index = MnemonicIndex::build(&lang.sleigh);
        let case_index = if !lang.sleigh.matchers.is_empty() {
            let root_matcher = &lang.sleigh.matchers[0];
            CaseMnemonicIndex::build(
                &lang.sleigh,
                lang.initial_ctx,
                &root_matcher.cases,
                root_matcher.token_size,
            )
        } else {
            CaseMnemonicIndex {
                by_mnemonic: HashMap::new(),
            }
        };

        Ok(Self {
            sleigh: lang.sleigh,
            initial_ctx: lang.initial_ctx,
            mnemonic_index,
            case_index,
        })
    }

    /// Disassemble bytes into a list of instructions.
    ///
    /// :param data: The bytes to disassemble.
    /// :param address: The base address of the first byte.
    /// :param count: Maximum number of instructions to disassemble (0 for all).
    /// :returns: A list of Instruction objects.
    pub fn disasm(&self, data: Vec<u8>, address: u64, count: u32) -> PyResult<Vec<Instruction>> {
        let mut result = Vec::new();
        let mut runtime = sleigh_runtime::Runtime::new_with_config(&RuntimeConfig {
            context: self.initial_ctx,
            ..Default::default()
        });

        let mut offset: usize = 0;
        let max_count = if count == 0 { usize::MAX } else { count as usize };

        while offset < data.len() && result.len() < max_count {
            let addr = address + offset as u64;
            let remaining = &data[offset..];

            match runtime.decode(&self.sleigh, addr, remaining) {
                Some(inst) => {
                    let size = inst.num_bytes() as usize;
                    if size == 0 {
                        break;
                    }

                    let disasm = runtime.disasm(&self.sleigh).unwrap_or("INVALID");
                    let mnemonic = extract_mnemonic(disasm).to_string();
                    let op_str = disasm[mnemonic.len()..].trim().to_string();
                    let insn_bytes = data[offset..offset + size].to_vec();

                    result.push(Instruction {
                        address: addr,
                        size: size as u32,
                        mnemonic,
                        op_str,
                        bytes: insn_bytes,
                    });

                    offset += size;
                }
                None => break,
            }
        }

        Ok(result)
    }

    /// Disassemble bytes and return lightweight tuples.
    ///
    /// :param data: The bytes to disassemble.
    /// :param address: The base address of the first byte.
    /// :param count: Maximum number of instructions to disassemble (0 for all).
    /// :returns: A list of (address, size, mnemonic, op_str) tuples.
    pub fn disasm_lite(
        &self,
        data: Vec<u8>,
        address: u64,
        count: u32,
    ) -> PyResult<Vec<(u64, u32, String, String)>> {
        let mut result = Vec::new();
        let mut runtime = sleigh_runtime::Runtime::new_with_config(&RuntimeConfig {
            context: self.initial_ctx,
            ..Default::default()
        });

        let mut offset: usize = 0;
        let max_count = if count == 0 { usize::MAX } else { count as usize };

        while offset < data.len() && result.len() < max_count {
            let addr = address + offset as u64;
            let remaining = &data[offset..];

            match runtime.decode(&self.sleigh, addr, remaining) {
                Some(inst) => {
                    let size = inst.num_bytes() as usize;
                    if size == 0 {
                        break;
                    }

                    let disasm = runtime.disasm(&self.sleigh).unwrap_or("INVALID");
                    let mnemonic = extract_mnemonic(disasm).to_string();
                    let op_str = disasm[mnemonic.len()..].trim().to_string();

                    result.push((addr, size as u32, mnemonic, op_str));
                    offset += size;
                }
                None => break,
            }
        }

        Ok(result)
    }

    /// Assemble a single instruction into bytes.
    ///
    /// Searches for an encoding by enumerating opcode byte combinations and
    /// decoding each candidate to compare against the target disassembly.
    ///
    /// :param assembly: The assembly text (e.g., "MOV EAX, 0x1").
    /// :param address: The address at which the instruction will be placed.
    /// :returns: The assembled bytes.
    pub fn asm(&self, assembly: &str, address: u64) -> PyResult<Vec<u8>> {
        let target = normalize_asm(assembly);
        if target.is_empty() {
            return Err(PyValueError::new_err("Empty assembly string"));
        }

        if self.sleigh.matchers.is_empty() {
            return Err(PyRuntimeError::new_err(
                "SLEIGH data not properly initialized",
            ));
        }

        // Validate the mnemonic is known
        let target_mnemonic = extract_mnemonic(&target).to_string();
        let target_op_str = target[target_mnemonic.len()..].trim();
        if self.mnemonic_index.get_constructors(&target_mnemonic).is_none() {
            return Err(PyValueError::new_err(format!(
                "Unknown mnemonic: {target_mnemonic}"
            )));
        }

        // Parse immediate values from operands
        let imm_values = parse_operand_values(target_op_str);

        let matcher = &self.sleigh.matchers[0];
        let token_size = matcher.token_size;
        let pad_len = token_size + 16;

        let mut runtime = sleigh_runtime::Runtime::new_with_config(&RuntimeConfig {
            context: self.initial_ctx,
            ..Default::default()
        });

        // Build immediate suffix options
        let imm_suffixes: Vec<Vec<u8>> = if imm_values.is_empty() {
            vec![vec![]]
        } else {
            let mut suffixes = vec![vec![]];
            for &v in &imm_values {
                let uv = v as u64;
                suffixes.push(vec![(uv & 0xFF) as u8]);
                suffixes.push((uv as u16).to_le_bytes().to_vec());
                suffixes.push((uv as u32).to_le_bytes().to_vec());
                suffixes.push(uv.to_le_bytes().to_vec());
                suffixes.push((uv as u16).to_be_bytes().to_vec());
                suffixes.push((uv as u32).to_be_bytes().to_vec());
            }
            suffixes
        };

        let mut best: Option<Vec<u8>> = None;
        let max_bits = (token_size * 8) as u32;
        let has_imm = !imm_values.is_empty();

        // Phase 1-2: brute-force enumerate 1-byte and 2-byte opcode prefixes
        // This handles most common instructions quickly
        for opcode_len in 1..=2usize {
            let total: u32 = 1u32 << (opcode_len * 8);

            for opcode_val in 0..total {
                let opcode_bytes: Vec<u8> = (0..opcode_len)
                    .map(|i| ((opcode_val >> (i * 8)) & 0xFF) as u8)
                    .collect();

                for suffix in &imm_suffixes {
                    let mut candidate = Vec::with_capacity(pad_len);
                    candidate.extend_from_slice(&opcode_bytes);
                    candidate.extend_from_slice(suffix);
                    candidate.resize(pad_len, 0);

                    if let Some(size) = try_decode_match(
                        &mut runtime,
                        &self.sleigh,
                        &candidate,
                        address,
                        &target,
                    ) {
                        let result = candidate[..size].to_vec();
                        if result.len() <= opcode_len {
                            return Ok(result);
                        }
                        if best.as_ref().is_none_or(|prev| result.len() < prev.len()) {
                            best = Some(result);
                        }
                    }
                }
            }

            if let Some(ref b) = best {
                if b.len() <= opcode_len {
                    return Ok(best.unwrap());
                }
            }
        }

        if best.is_some() {
            return Ok(best.unwrap());
        }

        // Phase 3: prefix + 2-byte opcode enumeration
        // Handles REX-prefixed instructions, operand/address overrides, etc.
        // Order: most common prefixes first for faster matching
        let prefixes: Vec<u8> = [
            0x48u8, // REX.W (most common for 64-bit ops)
            0x66, // Operand size override
            0x49, 0x4C, 0x4D, // REX.WB, REX.R, REX.RB
            0x41, 0x44, 0x45, // REX.B, REX.R, REX.RB
        ]
        .into_iter()
        .chain(
            (0x40..=0x4Fu8).filter(|b| !matches!(b, 0x48 | 0x49 | 0x4C | 0x4D | 0x41 | 0x44 | 0x45)),
        )
        .chain([0x67, 0xF0, 0xF2, 0xF3, 0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65].into_iter())
        .collect();

        for &prefix in &prefixes {
            for opcode_val in 0u32..65536 {
                let b1 = (opcode_val & 0xFF) as u8;
                let b2 = ((opcode_val >> 8) & 0xFF) as u8;

                for suffix in &imm_suffixes {
                    let mut candidate = Vec::with_capacity(pad_len);
                    candidate.push(prefix);
                    candidate.push(b1);
                    candidate.push(b2);
                    candidate.extend_from_slice(suffix);
                    candidate.resize(pad_len, 0);

                    if let Some(size) = try_decode_match(
                        &mut runtime,
                        &self.sleigh,
                        &candidate,
                        address,
                        &target,
                    ) {
                        let result = candidate[..size].to_vec();
                        let len = result.len();
                        if best.as_ref().is_none_or(|prev| len < prev.len()) {
                            best = Some(result);
                        }
                        if len <= 3 {
                            return Ok(best.unwrap());
                        }
                    }
                }
            }

            // If we found a result, return it after checking all opcodes for this prefix
            if best.is_some() {
                return Ok(best.unwrap());
            }
        }

        if best.is_some() {
            return Ok(best.unwrap());
        }

        // Phase 4: case-based search using SLEIGH matcher structure
        // This handles RISC architectures (ARM, MIPS, etc.) and any
        // remaining x86 instructions not found in earlier phases.
        let matching_ids: HashSet<u32> = self
            .mnemonic_index
            .get_constructors(&target_mnemonic)
            .unwrap()
            .iter()
            .copied()
            .collect();

        let mut candidate_cases: Vec<&MatchCase> = Vec::new();
        let mut seen: HashSet<usize> = HashSet::new();

        // From constructor mnemonic index
        for case in &matcher.cases {
            if matching_ids.contains(&case.constructor) {
                let ptr = case as *const _ as usize;
                if seen.insert(ptr) {
                    candidate_cases.push(case);
                }
            }
        }

        // From case probe index
        if let Some(case_indices) = self.case_index.get_cases(&target_mnemonic) {
            for &idx in case_indices {
                let case = &matcher.cases[idx];
                let ptr = case as *const _ as usize;
                if seen.insert(ptr) {
                    candidate_cases.push(case);
                }
            }
        }

        candidate_cases.sort_by_key(|c| free_bit_positions(c.token.mask, max_bits).len());

        for case in &candidate_cases {
            let free_count = free_bit_positions(case.token.mask, max_bits).len();
            // Cap at 2^20 (~1M) per case to keep search tractable
            let max_per_case: u64 = if free_count <= 20 {
                1u64 << free_count
            } else {
                1u64 << 20
            };

            let result = if has_imm {
                try_assemble_with_immediates(
                    &mut runtime,
                    &self.sleigh,
                    case,
                    token_size,
                    address,
                    &target,
                    &imm_values,
                    max_per_case,
                )
            } else {
                try_assemble_with_case(
                    &mut runtime,
                    &self.sleigh,
                    case,
                    token_size,
                    address,
                    &target,
                    max_per_case,
                )
            };

            if let Some(bytes) = result {
                return Ok(bytes);
            }
        }

        Err(PyValueError::new_err(format!(
            "Failed to assemble: {assembly}"
        )))
    }

    /// Assemble multiple instructions separated by semicolons or newlines.
    ///
    /// :param assembly: The assembly text with instructions separated by ';' or newlines.
    /// :param address: The base address for the first instruction.
    /// :returns: The assembled bytes for all instructions concatenated.
    pub fn asm_multi(&self, assembly: &str, address: u64) -> PyResult<Vec<u8>> {
        let mut result = Vec::new();
        let mut current_addr = address;

        for line in assembly.split(|c| c == ';' || c == '\n') {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let bytes = self.asm(line, current_addr)?;
            current_addr += bytes.len() as u64;
            result.extend_from_slice(&bytes);
        }

        Ok(result)
    }
}

/// Resolve the SLEIGH spec (ldef path, language ID) for a given architecture.
fn resolve_sleigh_spec(triple: &target_lexicon::Triple) -> Option<(&'static str, &'static str)> {
    use target_lexicon::{
        Aarch64Architecture, Architecture, ArmArchitecture, Mips32Architecture,
        Riscv32Architecture, Riscv64Architecture,
    };

    match triple.architecture {
        Architecture::Arm(variant) => {
            let ldef = "ARM/data/languages/ARM.ldefs";
            let id = match variant {
                ArmArchitecture::Arm => "ARM:LE:32:v8",
                ArmArchitecture::Armeb => "ARM:BE:32:v8",
                ArmArchitecture::Armv4 => "ARM:LE:32:v4",
                ArmArchitecture::Armv4t => "ARM:LE:32:v4t",
                ArmArchitecture::Armv5t
                | ArmArchitecture::Armv5te
                | ArmArchitecture::Armv5tej => "ARM:LE:32:v5t",
                ArmArchitecture::Armv6
                | ArmArchitecture::Armv6j
                | ArmArchitecture::Armv6k
                | ArmArchitecture::Armv6z
                | ArmArchitecture::Armv6kz
                | ArmArchitecture::Armv6t2
                | ArmArchitecture::Armv6m => "ARM:LE:32:v6",
                ArmArchitecture::Armv7
                | ArmArchitecture::Armv7a
                | ArmArchitecture::Armv7k
                | ArmArchitecture::Armv7ve
                | ArmArchitecture::Armv7m
                | ArmArchitecture::Armv7r
                | ArmArchitecture::Armv7s => "ARM:LE:32:v7",
                ArmArchitecture::Armebv7r => "ARM:BE:32:v7",
                ArmArchitecture::Armv8
                | ArmArchitecture::Armv8a
                | ArmArchitecture::Armv8_1a
                | ArmArchitecture::Armv8_2a
                | ArmArchitecture::Armv8_3a
                | ArmArchitecture::Armv8_4a
                | ArmArchitecture::Armv8_5a
                | ArmArchitecture::Armv8mBase
                | ArmArchitecture::Armv8mMain
                | ArmArchitecture::Armv8r => "ARM:LE:32:v8",
                ArmArchitecture::Thumbv4t
                | ArmArchitecture::Thumbv5te
                | ArmArchitecture::Thumbv6m
                | ArmArchitecture::Thumbv7a
                | ArmArchitecture::Thumbv7em
                | ArmArchitecture::Thumbv7m
                | ArmArchitecture::Thumbv7neon
                | ArmArchitecture::Thumbv8mBase
                | ArmArchitecture::Thumbv8mMain => "ARM:LE:32:v8T",
                ArmArchitecture::Thumbeb => "ARM:BE:32:v8T",
                _ => return None,
            };
            Some((ldef, id))
        }
        Architecture::Aarch64(variant) => {
            let ldef = "AARCH64/data/languages/AARCH64.ldefs";
            let id = match variant {
                Aarch64Architecture::Aarch64 => "AARCH64:LE:64:v8A",
                Aarch64Architecture::Aarch64be => "AARCH64:BE:64:v8A",
                _ => return None,
            };
            Some((ldef, id))
        }
        Architecture::M68k => {
            Some(("68000/data/languages/68000.ldefs", "68000:BE:32:Coldfire"))
        }
        Architecture::Mips32(variant) => {
            let ldef = "MIPS/data/languages/mips.ldefs";
            let id = match variant {
                Mips32Architecture::Mips => "MIPS:BE:32:default",
                Mips32Architecture::Mipsel => "MIPS:LE:32:default",
                Mips32Architecture::Mipsisa32r6 => "MIPS:BE:32:R6",
                Mips32Architecture::Mipsisa32r6el => "MIPS:LE:32:R6",
                _ => return None,
            };
            Some((ldef, id))
        }
        Architecture::Msp430 => Some((
            "TI_MSP430/data/languages/TI_MSP430.ldefs",
            "TI_MSP430X:LE:32:default",
        )),
        Architecture::Powerpc => Some((
            "PowerPC/data/languages/ppc.ldefs",
            "PowerPC:BE:32:default",
        )),
        Architecture::Powerpc64 => Some((
            "PowerPC/data/languages/ppc.ldefs",
            "PowerPC:BE:64:default",
        )),
        Architecture::Powerpc64le => Some((
            "PowerPC/data/languages/ppc.ldefs",
            "PowerPC:LE:64:default",
        )),
        Architecture::Riscv32(variant) => {
            let ldef = "RISCV/data/languages/riscv.ldefs";
            let id = match variant {
                Riscv32Architecture::Riscv32 => "RISCV:LE:32:default",
                Riscv32Architecture::Riscv32gc => "RISCV:LE:32:RV32GC",
                Riscv32Architecture::Riscv32i => "RISCV:LE:32:RV32I",
                Riscv32Architecture::Riscv32imc => "RISCV:LE:32:RV32IMC",
                _ => return None,
            };
            Some((ldef, id))
        }
        Architecture::Riscv64(variant) => {
            let ldef = "RISCV/data/languages/riscv.ldefs";
            let id = match variant {
                Riscv64Architecture::Riscv64 => "RISCV:LE:64:default",
                Riscv64Architecture::Riscv64gc => "RISCV:LE:64:RV64GC",
                _ => return None,
            };
            Some((ldef, id))
        }
        Architecture::X86_32(_) => {
            Some(("x86/data/languages/x86.ldefs", "x86:LE:32:default"))
        }
        Architecture::X86_64h | Architecture::X86_64 => {
            Some(("x86/data/languages/x86.ldefs", "x86:LE:64:default"))
        }
        Architecture::XTensa => Some((
            "xtensa/data/languages/xtensa.ldefs",
            "Xtensa:LE:32:default",
        )),
        _ => None,
    }
}

#[pymodule]
pub fn assembler(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<SleighAssembler>()?;
    m.add_class::<Instruction>()?;
    Ok(())
}
