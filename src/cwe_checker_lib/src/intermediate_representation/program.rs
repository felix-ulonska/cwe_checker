//! Representation of a disassembled binary.

use super::{Blk, Def, ExternSymbol, Jmp, Sub, Variable};
use crate::prelude::*;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// The `Program` structure represents a disassembled binary.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct Program {
    /// The known functions contained in the binary
    pub subs: BTreeMap<Tid, Term<Sub>>,
    /// Extern symbols linked to the binary by the linker.
    pub extern_symbols: BTreeMap<Tid, ExternSymbol>,
    /// Entry points into to binary,
    /// i.e. the term identifiers of functions that may be called from outside of the binary.
    pub entry_points: BTreeSet<Tid>,
    /// An offset that has been added to all addresses in the program compared to the addresses
    /// as specified in the binary file.
    ///
    /// In certain cases, e.g. if the binary specifies a segment to be loaded at address 0,
    /// the Ghidra backend may shift the whole binary image by a constant value in memory.
    /// Thus addresses as specified by the binary and addresses as reported by Ghidra may differ by a constant offset,
    /// which is stored in this value.
    pub address_base_offset: u64,
}

impl Program {
    /// Returns an iterator over the functions in this program.
    pub fn functions(&self) -> impl Iterator<Item = &Term<Sub>> {
        self.subs.values().into_iter()
    }

    /// Returns an iterator over the functions in this program.
    pub fn functions_mut(&mut self) -> impl Iterator<Item = &mut Term<Sub>> {
        self.subs.values_mut().into_iter()
    }

    /// Returns an iterator over the returning functions in this program.
    pub fn ret_functions(&self) -> impl Iterator<Item = &Term<Sub>> {
        self.subs
            .values()
            .into_iter()
            .filter(|f| !f.is_non_returning())
    }

    /// Returns an iterator over the returning functions in this program.
    pub fn ret_functions_mut(&mut self) -> impl Iterator<Item = &mut Term<Sub>> {
        self.subs
            .values_mut()
            .into_iter()
            .filter(|f| !f.is_non_returning())
    }

    /// Returns the number of functions in this program.
    pub fn num_functions(&self) -> u64 {
        self.subs.len() as u64
    }

    /// Returns an iterator over all blocks in the program.
    pub fn blocks(&self) -> impl Iterator<Item = &Term<Blk>> {
        self.subs.values().flat_map(|func| func.term.blocks.iter())
    }

    /// Returns an iterator over all blocks in the program together with the
    /// TID of the funtion that contains them.
    pub fn blocks_with_fn_tid(&self) -> impl Iterator<Item = (&Tid, &Term<Blk>)> {
        self.subs
            .values()
            .flat_map(|func| std::iter::repeat(&func.tid).zip(func.term.blocks.iter()))
    }

    /// Returns an iterator over all blocks in the program.
    pub fn blocks_mut(&mut self) -> impl Iterator<Item = &mut Term<Blk>> {
        self.subs
            .values_mut()
            .flat_map(|func| func.term.blocks.iter_mut())
    }

    /// Returns an iterator over all blocks in the program together with the
    /// TID of the funtion that contains them.
    pub fn blocks_mut_with_fn_tid(&mut self) -> impl Iterator<Item = (&Tid, &mut Term<Blk>)> {
        self.subs
            .values_mut()
            .flat_map(|func| std::iter::repeat(&func.tid).zip(func.term.blocks.iter_mut()))
    }

    pub fn jmps(&self) -> impl Iterator<Item = &Term<Jmp>> {
        self.blocks().flat_map(|b| b.jmps())
    }

    pub fn jmps_with_fn_tid(&self) -> impl Iterator<Item = (&Tid, &Term<Jmp>)> {
        self.blocks_with_fn_tid()
            .flat_map(|(fn_tid, b)| std::iter::repeat(fn_tid).zip(b.jmps()))
    }

    pub fn jmps_mut(&mut self) -> impl Iterator<Item = &mut Term<Jmp>> {
        self.blocks_mut().flat_map(|b| b.jmps_mut())
    }

    pub fn jmps_mut_with_fn_tid(&mut self) -> impl Iterator<Item = (&Tid, &mut Term<Jmp>)> {
        self.blocks_mut_with_fn_tid()
            .flat_map(|(fn_tid, b)| std::iter::repeat(fn_tid).zip(b.jmps_mut()))
    }

    /// Returns the set of all variables used in the program.
    pub fn all_variables(&self) -> BTreeSet<Variable> {
        self.functions()
            .flat_map(|f| f.blocks())
            .flat_map(|b| b.defs())
            .filter_map(|d| match &d.term {
                Def::Assign { var, value: expr } | Def::Load { var, address: expr } => {
                    let mut vars = expr.input_vars();
                    vars.push(var);

                    Some(vars.into_iter())
                }
                Def::Store {
                    address: expr0,
                    value: expr1,
                } => {
                    let mut vars0 = expr0.input_vars();
                    let vars1 = expr1.input_vars();
                    vars0.extend(vars1);

                    Some(vars0.into_iter())
                }
            })
            .chain(
                self.functions()
                    .flat_map(|f| f.blocks())
                    .flat_map(|b| b.jmps())
                    .filter_map(|j| match &j.term {
                        Jmp::BranchInd(expr)
                        | Jmp::CBranch {
                            condition: expr, ..
                        }
                        | Jmp::CallInd { target: expr, .. } => Some(expr.input_vars().into_iter()),
                        _ => None,
                    }),
            )
            .flatten()
            .cloned()
            .collect()
    }

    /// Find a block term by its term identifier.
    /// WARNING: The function simply iterates through all blocks,
    /// i.e. it is very inefficient for large projects!
    pub fn find_block(&self, tid: &Tid) -> Option<&Term<Blk>> {
        self.subs
            .iter()
            .flat_map(|(_, sub)| sub.term.blocks.iter())
            .find(|block| block.tid == *tid)
    }

    /// Find the sub containing a specific jump instruction (including call instructions).
    /// WARNING: The function simply iterates though all blocks,
    /// i.e. it is very inefficient for large projects!
    pub fn find_sub_containing_jump(&self, jmp_tid: &Tid) -> Option<Tid> {
        for sub in self.subs.values() {
            for blk in &sub.term.blocks {
                for jmp in &blk.term.jmps {
                    if &jmp.tid == jmp_tid {
                        return Some(sub.tid.clone());
                    }
                }
            }
        }

        None
    }

    #[cfg(not(debug_assertions))]
    #[inline]
    pub fn debug_assert_invariants(&self) {}

    #[cfg(debug_assertions)]
    pub fn debug_assert_invariants(&self) {
        // Check that the mapping from function TIDs to function terms is
        // consistent.
        for (
            fn_tid_key,
            Term {
                tid: fn_tid_value, ..
            },
        ) in self.subs.iter()
        {
            assert_eq!(
                fn_tid_key, fn_tid_value,
                "Inconsistent function mapping: {} -> {}.",
                fn_tid_key, fn_tid_value
            );
        }
    }
}

impl fmt::Display for Program {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for Term { tid, term: sub } in self.subs.values() {
            writeln!(
                f,
                "FN [{}] name:{} entry:{} non_returning:{}",
                tid,
                sub.name,
                if self.entry_points.contains(tid) {
                    "yes"
                } else {
                    "no"
                },
                if sub.is_non_returning() { "yes" } else { "no" },
            )?;
            for Term { tid, term: blk } in sub.blocks.iter() {
                writeln!(f, "  BLK [{}]", tid)?;
                for Term { tid, term: def } in blk.defs.iter() {
                    writeln!(f, "    DEF [{}] {}", tid, def)?;
                }
                for Term { tid, term: jmp } in blk.jmps.iter() {
                    writeln!(f, "    JMP [{}] {}", tid, jmp)?;
                }
            }
        }
        for ext in self.extern_symbols.values() {
            writeln!(f, "EXT {}", ext)?;
        }
        Ok(())
    }
}
