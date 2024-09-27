use super::*;
use crate::utils::log::LogMessage;
use std::{collections::HashSet, fmt};

/// A basic block is a sequence of `Def` instructions followed by up to two
/// `Jmp` instructions.
///
/// The `Def` instructions represent side-effectful operations that are executed
/// in order when the block is entered. `Def` instructions do not affect the
/// control flow of a program.
///
/// The `Jmp` instructions represent control flow affecting operations.
/// There can only be zero, one or two `Jmp`s:
///
/// - Zero `Jmp`s indicate that the next execution to be executed could not be
///   discerned. This should only happen on disassembler errors or on dead ends
///   in the control flow graph that were deliberately inserted by the user.
/// - If there is exactly one `Jmp`, it is required to be an unconditional jump.
/// - For two jumps, the first one has to be a conditional jump, where the
///   second unconditional jump is only taken if the condition of the first
///   jump evaluates to false.
///
/// If one of the `Jmp` instructions is an indirect jump,
/// then the `indirect_jmp_targets` is a list of possible jump target addresses
/// for that jump. The list may not be complete and the entries are not
/// guaranteed to be correct.
///
/// Basic blocks are *single entry, single exit*, i.e. a basic block is only
/// entered at the beginning and is only exited by the jump instructions at the
/// end of the block. If a new control flow edge is discovered that would jump
/// to the middle of a basic block, the block structure needs to be updated
/// accordingly.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Blk {
    /// The `Def` instructions of the basic block in order of execution.
    pub defs: Vec<Term<Def>>,
    /// The `Jmp` instructions of the basic block
    pub jmps: Vec<Term<Jmp>>,
    /// If the basic block contains an indirect jump,
    /// this field contains possible jump target addresses for the jump.
    ///
    /// Note that possible targets of indirect calls are *not* contained,
    /// i.e., only intraprocedural jump targets are contained in this field.
    pub indirect_jmp_targets: Vec<Tid>,
}

impl Default for Blk {
    fn default() -> Self {
        Self::new()
    }
}

impl Blk {
    /// Returns an empty block.
    pub fn new() -> Blk {
        Blk {
            defs: vec![],
            jmps: vec![],
            indirect_jmp_targets: vec![],
        }
    }

    /// Returns an iterator over the jumps in this block.
    pub fn jmps(&self) -> impl Iterator<Item = &Term<Jmp>> {
        self.jmps.iter()
    }

    /// Returns an iterator over the jumps in this block.
    pub fn jmps_mut(&mut self) -> impl Iterator<Item = &mut Term<Jmp>> {
        self.jmps.iter_mut()
    }

    /// Returns an iterator over the defs in this block.
    pub fn defs(&self) -> impl Iterator<Item = &Term<Def>> {
        self.defs.iter()
    }

    /// Returns an iterator over the defs in this block.
    pub fn defs_mut(&mut self) -> impl Iterator<Item = &mut Term<Def>> {
        self.defs.iter_mut()
    }

    /// Returns the number of instructions (defs and jumps) in this basic block.
    pub fn num_insn(&self) -> u64 {
        (self.defs.len() + self.jmps.len()) as u64
    }

    /// Returns the target of all direct calls in this block.
    pub fn get_call_targets(&self) -> Option<Vec<&Tid>> {
        match self.jmps.as_slice() {
            [Term {
                term: Jmp::Call { target, .. },
                ..
            }] => Some(vec![target]),
            _ => None,
        }
    }

    /// Returns the set of all constants that are used by instructions in the
    /// block.
    pub fn referenced_constants(&self) -> Vec<Bitvector> {
        self.defs()
            .map(|d| d.referenced_constants())
            .chain(self.jmps().map(|j| j.referenced_constants()))
            .fold(Vec::new(), |mut acc, c| {
                if let Some(c) = c {
                    acc.extend(c)
                }

                acc
            })
    }
}

/// The different kinds of sinks in a CFG.
pub enum SinkType {
    /// Target of broken control flow transfers.
    ArtificialSink,
    /// Return target of calls to noreturn functions.
    ArtificialReturnTarget,
    /// A function return site.
    ReturnSite,
    /// An endless loop.
    SelfLoop,
}

impl Term<Blk> {
    /// Returns the [`SinkType`] of this block, if it is a sink.
    pub fn get_sink_type(&self) -> Option<SinkType> {
        match self.term.jmps.as_slice() {
            _ if self.tid.is_artificial_sink_block() => Some(SinkType::ArtificialSink),
            _ if self.tid.is_artificial_return_target_block() => {
                Some(SinkType::ArtificialReturnTarget)
            }
            // Unconditional self-loops.
            [Term {
                term:
                    Jmp::CBranch {
                        target: cond_target,
                        ..
                    },
                ..
            }, Term {
                term: Jmp::Branch(target),
                ..
            }] if target == cond_target && target == &self.tid => Some(SinkType::SelfLoop),
            [Term {
                term: Jmp::Branch(target),
                ..
            }] if target == &self.tid => Some(SinkType::SelfLoop),
            [Term {
                term: Jmp::Return(_),
                ..
            }] => Some(SinkType::ReturnSite),
            _ => None,
        }
    }

    /// Return a clone of `self` where the given suffix is appended to the TIDs
    /// of all contained terms (the block itself and all `Jmp`s and `Def`s).
    ///
    /// Note that all TIDs of jump targets (direct, indirect and return targets)
    /// are left unchanged.
    pub fn clone_with_tid_suffix(&self, suffix: &str) -> Self {
        let mut cloned_block = self.clone();
        cloned_block.tid = cloned_block.tid.with_id_suffix(suffix);
        for def in cloned_block.term.defs.iter_mut() {
            def.tid = def.tid.clone().with_id_suffix(suffix);
        }
        for jmp in cloned_block.term.jmps.iter_mut() {
            jmp.tid = jmp.tid.clone().with_id_suffix(suffix);
        }
        cloned_block
    }

    /// Remove indirect jump target addresses for which no corresponding target
    /// block exists.
    ///
    /// Returns an error message for each removed address.
    pub fn remove_nonexisting_indirect_jump_targets(
        &mut self,
        all_jump_targets: &HashSet<Tid>,
    ) -> Result<(), Vec<LogMessage>> {
        let mut logs = Vec::new();

        self.term.indirect_jmp_targets = self
            .term
            .indirect_jmp_targets
            .iter()
            .filter_map(|target| {
                if all_jump_targets.contains(target) {
                    Some(target.clone())
                } else {
                    let error_msg = format!(
                        "Indirect jump target at {} does not exist",
                        target.address()
                    );
                    logs.push(LogMessage::new_error(error_msg).location(self.tid.clone()));
                    None
                }
            })
            .collect();

        if logs.is_empty() {
            Ok(())
        } else {
            Err(logs)
        }
    }

    /// Returns a new artificial sink block with the given suffix attached to
    /// its TID.
    ///
    /// The given suffix is also attached to the ID of all instructions in the
    /// block.
    pub fn artificial_sink(id_suffix: &str) -> Self {
        let blk_tid = Tid::artificial_sink_block(id_suffix);

        // Self-loop.
        let mut jmps = Vec::with_capacity(1);
        jmps.push(Term::<Jmp>::new(
            Tid::artificial_instr_with_suffix(format!("_{}", blk_tid)),
            Jmp::Branch(blk_tid.clone()),
        ));

        Self {
            tid: blk_tid,
            term: Blk {
                defs: Vec::with_capacity(0),
                jmps,
                indirect_jmp_targets: Vec::with_capacity(0),
            },
        }
    }

    /// Returns a new artificial return target block with the given suffix
    /// attached to its ID.
    pub fn artificial_return_target(id_suffix: &str) -> Self {
        let blk_tid = Tid::artificial_return_target(id_suffix);

        // Self-loop.
        let mut jmps = Vec::with_capacity(1);
        jmps.push(Term::<Jmp>::new(
            Tid::artificial_instr_with_suffix(format!("_{}", blk_tid)),
            Jmp::Branch(blk_tid.clone()),
        ));

        Self {
            tid: blk_tid,
            term: Blk {
                defs: Vec::with_capacity(0),
                jmps,
                indirect_jmp_targets: Vec::with_capacity(0),
            },
        }
    }
}

impl fmt::Display for Blk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for Term { tid, term: def } in self.defs.iter() {
            writeln!(f, "DEF [{}] {}", tid, def)?;
        }
        for Term { tid, term: jmp } in self.jmps.iter() {
            writeln!(f, "JMP [{}] {}", tid, jmp)?;
        }
        Ok(())
    }
}
