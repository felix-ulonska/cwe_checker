use super::*;
use crate::utils::log::LogMessage;
use std::ops::Deref;
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
    /// Iff the basic block ends in an indirect jump or call, this field
    /// contains possible target addresses.
    ///
    /// In general, this list is neither complete nor sound, i.e., it may
    /// contain targets that are infeasible at runtime and miss targets that may
    /// be observed.
    indirect_control_flow_targets: Option<Box<IndirectCfTargets>>,
}

/// Possible targets of an indirect control flow transfer.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub enum IndirectCfTargets {
    /// An indirect call.
    Call(IndirectCallTargets),
    /// An indirect jump.
    Jump(IndirectJumpTargets),
}

impl IndirectCfTargets {
    /// Returns an iterator over the possible targets of the indirect jump at
    /// the end of this block.
    pub fn iter_ind_jump_targets(&self) -> Option<impl Iterator<Item = &BlockTid>> {
        match self {
            IndirectCfTargets::Jump(ts) => Some(ts.as_ref().iter()),
            _ => None,
        }
    }

    /// Returns an iterator over the possible targets of the indirect jump at
    /// the end of this block.
    pub fn iter_ind_jump_targets_mut(&mut self) -> Option<impl Iterator<Item = &mut BlockTid>> {
        match self {
            IndirectCfTargets::Jump(ts) => Some(ts.as_mut().iter_mut()),
            _ => None,
        }
    }

    /// Returns an iterator over the possible targets of the indirect call at
    /// the end of this block.
    pub fn iter_ind_call_targets(&self) -> Option<impl Iterator<Item = &FunctionTid>> {
        match self {
            IndirectCfTargets::Call(x) => Some(x.as_ref().iter()),
            _ => None,
        }
    }

    /// Returns an iterator over the possible targets of the indirect call at
    /// the end of this block.
    pub fn iter_ind_call_targets_mut(&mut self) -> Option<impl Iterator<Item = &mut FunctionTid>> {
        match self {
            IndirectCfTargets::Call(x) => Some(x.as_mut().iter_mut()),
            _ => None,
        }
    }
}

/// Targets of an indirect call.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct IndirectCallTargets(Vec<FunctionTid>);
/// Targets of an indirect jump.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct IndirectJumpTargets(Vec<BlockTid>);

impl Deref for IndirectCallTargets {
    type Target = [FunctionTid];

    fn deref(&self) -> &[FunctionTid] {
        &self.0
    }
}

impl Deref for IndirectJumpTargets {
    type Target = [BlockTid];

    fn deref(&self) -> &[BlockTid] {
        &self.0
    }
}

impl<T> AsRef<T> for IndirectCallTargets
where
    T: ?Sized,
    <IndirectCallTargets as Deref>::Target: AsRef<T>,
{
    fn as_ref(&self) -> &T {
        self.deref().as_ref()
    }
}

impl<T> AsRef<T> for IndirectJumpTargets
where
    T: ?Sized,
    <IndirectJumpTargets as Deref>::Target: AsRef<T>,
{
    fn as_ref(&self) -> &T {
        self.deref().as_ref()
    }
}

// Can we use `dyn Tid` after refactoring of `Tid` type?
impl AsRef<[Tid]> for IndirectCfTargets {
    fn as_ref(&self) -> &[Tid] {
        match self {
            IndirectCfTargets::Jump(x) => x.as_ref(),
            IndirectCfTargets::Call(x) => x.as_ref(),
        }
    }
}

impl AsMut<Vec<FunctionTid>> for IndirectCallTargets {
    fn as_mut(&mut self) -> &mut Vec<FunctionTid> {
        &mut self.0
    }
}

impl AsMut<Vec<BlockTid>> for IndirectJumpTargets {
    fn as_mut(&mut self) -> &mut Vec<BlockTid> {
        &mut self.0
    }
}

impl<T: Iterator<Item = FunctionTid>> From<T> for IndirectCallTargets {
    fn from(iter: T) -> Self {
        iter.collect()
    }
}

impl<T: Iterator<Item = BlockTid>> From<T> for IndirectJumpTargets {
    fn from(iter: T) -> Self {
        iter.collect()
    }
}

impl FromIterator<FunctionTid> for IndirectCallTargets {
    fn from_iter<T: IntoIterator<Item = FunctionTid>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl FromIterator<BlockTid> for IndirectJumpTargets {
    fn from_iter<T: IntoIterator<Item = BlockTid>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl IntoIterator for IndirectCallTargets {
    type Item = FunctionTid;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl IntoIterator for IndirectJumpTargets {
    type Item = BlockTid;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
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
            indirect_control_flow_targets: None,
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

    /// Sets the possible targets of the indirect jump at the end of this block.
    pub fn set_ind_jump_targets<T>(&mut self, v: T) -> &mut Self
    where
        T: IntoIterator<Item = BlockTid>,
    {
        debug_assert!(matches!(
            self.jmps.first().map(|j| &j.term),
            Some(Jmp::BranchInd(_))
        ));

        self.indirect_control_flow_targets = Some(Box::new(IndirectCfTargets::Jump(
            IndirectJumpTargets::from_iter(v),
        )));

        self
    }

    /// Sets the possible targets of the indirect call at the end of this block.
    pub fn set_ind_call_targets<T>(&mut self, v: T) -> &mut Self
    where
        T: IntoIterator<Item = FunctionTid>,
    {
        debug_assert!(matches!(
            self.jmps.first().map(|j| &j.term),
            Some(Jmp::CallInd { .. })
        ));

        self.indirect_control_flow_targets = Some(Box::new(IndirectCfTargets::Call(
            IndirectCallTargets::from_iter(v),
        )));

        self
    }

    /// Clears the possible targets of the indirect control flow transfer at the
    /// end of this block.
    pub fn clear_ind_control_flow_targets(&mut self) -> &mut Self {
        self.indirect_control_flow_targets = None;

        self
    }

    /// Returns the possible targets of the indirect control flow transfer at
    /// the end of this block.
    pub fn ind_control_flow_targets(&self) -> Option<&IndirectCfTargets> {
        self.indirect_control_flow_targets.as_deref()
    }

    /// Returns the possible targets of the indirect control flow transfer at
    /// the end of this block.
    pub fn ind_control_flow_targets_mut(&mut self) -> Option<&mut IndirectCfTargets> {
        self.indirect_control_flow_targets.as_deref_mut()
    }

    /// Returns the possible targets of the indirect jump at the end of this
    /// block.
    pub fn ind_jump_targets(&self) -> Option<impl Iterator<Item = &BlockTid>> {
        self.ind_control_flow_targets()
            .and_then(|x| x.iter_ind_jump_targets())
    }

    /// Returns the possible targets of the indirect jump at the end of this
    /// block.
    pub fn ind_jump_targets_targets_mut(&mut self) -> Option<impl Iterator<Item = &mut BlockTid>> {
        self.ind_control_flow_targets_mut()
            .and_then(|x| x.iter_ind_jump_targets_mut())
    }

    /// Returns the possible targets of the indirect call at the end of this
    /// block.
    pub fn ind_call_targets(&self) -> Option<impl Iterator<Item = &FunctionTid>> {
        self.ind_control_flow_targets()
            .and_then(|x| x.iter_ind_call_targets())
    }

    /// Returns the possible targets of the indirect call at the end of this
    /// block.
    pub fn ind_call_targets_targets_mut(
        &mut self,
    ) -> Option<impl Iterator<Item = &mut FunctionTid>> {
        self.ind_control_flow_targets_mut()
            .and_then(|x| x.iter_ind_call_targets_mut())
    }

    /// Adds the jumps to the end of the block.
    pub fn add_jumps<T>(&mut self, jmps: T) -> &mut Self
    where
        T: IntoIterator<Item = Term<Jmp>>,
    {
        self.jmps.extend(jmps);

        self
    }

    /// Adds the defs to the end of the block.
    pub fn add_defs<T>(&mut self, defs: T) -> &mut Self
    where
        T: IntoIterator<Item = Term<Def>>,
    {
        self.defs.extend(defs);

        self
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

    /// Removes indirect control flow targets that do not exist.
    ///
    /// Returns an error message for each removed address.
    pub fn remove_nonexisting_indirect_cf_targets(
        &mut self,
        all_jump_targets: &HashSet<BlockTid>,
        all_call_targets: &HashSet<FunctionTid>,
    ) -> Vec<LogMessage> {
        let mut logs = Vec::with_capacity(0);

        self.term.indirect_control_flow_targets =
            self.term.indirect_control_flow_targets.as_ref().map(|b| {
                Box::new(match &**b {
                    IndirectCfTargets::Call(indirect_call_targets) => IndirectCfTargets::Call(
                        indirect_call_targets
                            .iter()
                            .filter_map(|target| {
                                if all_call_targets.contains(target) {
                                    Some(target.clone())
                                } else {
                                    let error_msg = format!(
                                        "Indirect call target at {} does not exist",
                                        target.address()
                                    );
                                    logs.push(
                                        LogMessage::new_error(error_msg).location(self.tid.clone()),
                                    );
                                    None
                                }
                            })
                            .collect(),
                    ),
                    IndirectCfTargets::Jump(indirect_jump_targets) => IndirectCfTargets::Jump(
                        indirect_jump_targets
                            .iter()
                            .filter_map(|target| {
                                if all_jump_targets.contains(target) {
                                    Some(target.clone())
                                } else {
                                    let error_msg = format!(
                                        "Indirect jump target at {} does not exist",
                                        target.address()
                                    );
                                    logs.push(
                                        LogMessage::new_error(error_msg).location(self.tid.clone()),
                                    );
                                    None
                                }
                            })
                            .collect(),
                    ),
                })
            });

        logs
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
                indirect_control_flow_targets: None,
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
                indirect_control_flow_targets: None,
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
