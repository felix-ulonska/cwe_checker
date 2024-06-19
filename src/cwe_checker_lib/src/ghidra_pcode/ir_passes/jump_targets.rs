use crate::intermediate_representation::{
    BlockTid, FunctionTid, Jmp as IrJmp, Program as IrProgram, Term, Tid,
};

use super::prelude::*;

use std::collections::{HashMap, HashSet};

/// Patches control flow to nonexisting targets.
///
/// - Adds an artificial sink block to each nonempty function.
/// - Rewrites returns and branches to (intraprocedurally) nonexisting targets
///   to the artificial sink block.
/// - Removes nonexisting indirect jump targets.
/// - Removes nonexisting indirect call targets.
///
/// # Postconditions
///
/// 1. All intraprocedural CFTs exist within the enclosing function.
/// 2. All interprocedural CFTs exist within the program.
/// 3. Every function has zero or one artificial sink blocks. [All its incoming
///    edges are from broken intraprocedural CFTs.]
///
/// # Run After
///
/// - Inlining. [Might invalidate 3rd Postcondition.]
///   [InliningPass](super::InliningPass)
/// - Artifical sink function has been added.
///   [RemoveEmptyFunctionsPass](super::RemoveEmptyFunctionsPass)
pub struct PatchCfPass {
    /// Valid call targets.
    fn_tids: HashSet<FunctionTid>,
    /// Valid intraprocedural jump targets.
    fn_tids_to_blk_tids: HashMap<FunctionTid, HashSet<BlockTid>>,
    /// Valid interprocedural jump targets.
    blk_tids: HashSet<BlockTid>,
}

impl IrPass for PatchCfPass {
    const NAME: &'static str = "PatchCfPass";
    const DBG_IR_FORM: debug::IrForm = debug::IrForm::CfPatched;

    type Input = Program;
    type ConstructionInput = Self::Input;

    fn new(program: &Self::ConstructionInput) -> Self {
        let ret = Self {
            fn_tids: program
                .functions()
                .map(|f| f.tid.clone())
                .chain(program.extern_symbols.keys().cloned())
                .collect(),
            fn_tids_to_blk_tids: program
                .functions()
                .map(|f| (f.tid.clone(), f.blocks().map(|b| b.tid.clone()).collect()))
                .collect(),
            blk_tids: program.blocks().map(|b| b.tid.clone()).collect(),
        };

        ret
    }

    fn run(&mut self, program: &mut Self::Input) -> Vec<LogMessage> {
        // Add an artificial sink block to each nonempty function.
        for f in program
            .functions_mut()
            .filter(|f| !f.blocks.is_empty() && !f.tid.is_artificial_sink_fn())
        {
            f.add_artifical_sink();
            self.blk_tids
                .insert(Tid::artificial_sink_block_for_fn(&f.tid));
            self.fn_tids_to_blk_tids
                .get_mut(&f.tid)
                .unwrap()
                .insert(Tid::artificial_sink_block_for_fn(&f.tid));
        }

        // Rewrite branches and returns to intraprocedurally nonexisting blocks
        // to artificial sink of the surrounding function.
        let mut logs = self.retarget_wild_returns(program);
        logs.extend(self.retarget_wild_branches(program));
        // Retarget calls to nonexisting functions to artificial sink funtion.
        logs.extend(self.retarget_wild_calls(program));

        if cfg!(debug_assertions) {
            self.run_sanity_checks(program);
        }

        logs
    }

    fn assert_postconditions(construction_input: &Self::ConstructionInput, program: &Self::Input) {
        let pass = Self::new(construction_input);

        // 1. All intraprocedural CFTs exist within the enclosing function.
        assert!(pass.find_wild_returns(program).1.is_empty());
        assert!(pass.find_wild_branches(program).1.is_empty());

        // 2. All interprocedural CFTs exist within the program.
        assert!(pass.find_wild_calls(program).1.is_empty());

        // 3. Every nonempty function has zero or one artificial sink blocks.
        //    [All its incoming edges are from broken intraprocedural CFTs.]
        for f in program.functions().filter(|f| !f.blocks.is_empty()) {
            let num_artificial_sinks = f
                .blocks()
                .filter(|b| b.tid.is_artificial_sink_block())
                .count();
            assert!(num_artificial_sinks == 0 || num_artificial_sinks == 1);
        }
    }
}

impl PatchCfPass {
    fn retarget_wild_returns(&self, program: &mut IrProgram) -> Vec<LogMessage> {
        let (logs, wild_returns) = self.find_wild_returns(program);

        for (fn_tid, Term { term: j, .. }) in program
            .jmps_mut_with_fn_tid()
            .filter(|(_, j)| wild_returns.contains(&j.tid))
        {
            match j {
                IrJmp::Call {
                    return_: Some(ret), ..
                }
                | IrJmp::CallInd {
                    return_: Some(ret), ..
                }
                | IrJmp::CallOther {
                    return_: Some(ret), ..
                } => *ret = Tid::artificial_sink_block_for_fn(fn_tid),
                _ => panic!(),
            }
        }

        logs
    }

    fn retarget_wild_branches(&self, program: &mut IrProgram) -> Vec<LogMessage> {
        let (mut logs, wild_branches) = self.find_wild_branches(program);

        for (fn_tid, Term { term: j, .. }) in program
            .blocks_mut_with_fn_tid()
            .flat_map(|(fn_tid, b)| {
                // FIXME: Dirty hack to do this here ... but hey, it works.
                logs.extend(b.remove_nonexisting_indirect_cf_targets(
                    self.fn_tids_to_blk_tids.get(fn_tid).unwrap(),
                    &self.fn_tids,
                ));

                std::iter::repeat(fn_tid).zip(b.term.jmps_mut())
            })
            .filter(|(_, j)| wild_branches.contains(&j.tid))
        {
            match j {
                IrJmp::Branch(target) | IrJmp::CBranch { target, .. } => {
                    *target = Tid::artificial_sink_block_for_fn(fn_tid)
                }
                _ => core::unreachable!(),
            }
        }

        logs
    }

    fn retarget_wild_calls(&self, program: &mut IrProgram) -> Vec<LogMessage> {
        let (logs, wild_calls) = self.find_wild_calls(program);

        for Term { term: j, .. } in program.jmps_mut().filter(|j| wild_calls.contains(&j.tid)) {
            match j {
                IrJmp::Call { target, .. } => *target = Tid::artificial_sink_fn(),
                _ => core::unreachable!(),
            }
        }

        logs
    }

    fn find_wild_returns(&self, program: &IrProgram) -> (Vec<LogMessage>, HashSet<Tid>) {
        program
            .blocks_with_fn_tid()
            .flat_map(|(f_tid, b)| std::iter::repeat(f_tid).zip(b.term.jmps()))
            .filter_map(|(f_tid, j)| match &j.term {
                IrJmp::Call {
                    return_: Some(ret), ..
                }
                | IrJmp::CallInd {
                    return_: Some(ret), ..
                }
                | IrJmp::CallOther {
                    return_: Some(ret), ..
                } if !self.fn_tids_to_blk_tids.get(f_tid).unwrap().contains(ret) => {
                    if !self.blk_tids.contains(ret) {
                        Some((
                            LogMessage::new_info(format!(
                                "{}: Return site of call at {} does not exist: {}",
                                Self::NAME,
                                j.tid,
                                j.term,
                            )),
                            j.tid.clone(),
                        ))
                    } else {
                        Some((
                            LogMessage::new_info(format!(
                                "{}: Return site of call at {} exists but is not within {}: {}",
                                Self::NAME,
                                j.tid,
                                f_tid,
                                j.term,
                            )),
                            j.tid.clone(),
                        ))
                    }
                }
                _ => None,
            })
            .collect()
    }

    fn find_wild_branches(&self, program: &IrProgram) -> (Vec<LogMessage>, HashSet<Tid>) {
        program
            .blocks_with_fn_tid()
            .flat_map(|(fn_tid, b)| std::iter::repeat(fn_tid).zip(b.term.jmps()))
            .filter_map(|(fn_tid, j)| match &j.term {
                IrJmp::CBranch { target, .. } | IrJmp::Branch(target)
                    if !self
                        .fn_tids_to_blk_tids
                        .get(fn_tid)
                        .unwrap()
                        .contains(target) =>
                {
                    if !self.blk_tids.contains(target) {
                        Some((
                            LogMessage::new_info(format!(
                                "{}: Target of branch at {} does not exist: {}",
                                Self::NAME,
                                j.tid,
                                j.term,
                            )),
                            j.tid.clone(),
                        ))
                    } else {
                        Some((
                            LogMessage::new_info(format!(
                                "{}: Target of branch at {} exists but is not within {}: {}",
                                Self::NAME,
                                j.tid,
                                fn_tid,
                                j.term,
                            )),
                            j.tid.clone(),
                        ))
                    }
                }
                _ => None,
            })
            .collect()
    }

    fn find_wild_calls(&self, program: &IrProgram) -> (Vec<LogMessage>, HashSet<Tid>) {
        program
            .jmps()
            .filter_map(|j| {
                let IrJmp::Call { target, .. } = &j.term else {
                    return None;
                };
                if self.fn_tids.contains(target) {
                    None
                } else {
                    Some((
                        LogMessage::new_info(format!(
                            "{}: Target of call at {} does not exist: {}",
                            Self::NAME,
                            j.tid,
                            j.term,
                        )),
                        j.tid.clone(),
                    ))
                }
            })
            .collect()
    }

    fn run_sanity_checks(&self, program: &IrProgram) {
        assert_eq!(
            self.fn_tids.len() as u64,
            program.num_functions() + program.extern_symbols.len() as u64,
            "Function TIDs are not unique."
        );
        assert_eq!(
            self.blk_tids.len(),
            program.blocks().count(),
            "Block TIDs are not unique."
        );

        let mut known_insn_tids = HashMap::new();
        for (fn_tid, blk_tid, insn_tid) in program.blocks_with_fn_tid().flat_map(|(f, b)| {
            b.defs
                .iter()
                .map(move |d| (f, &b.tid, &d.tid))
                .chain(b.jmps.iter().map(move |j| (f, &b.tid, &j.tid)))
        }) {
            match known_insn_tids.entry(insn_tid) {
                std::collections::hash_map::Entry::Vacant(e) => {
                    e.insert((fn_tid, blk_tid));
                }
                std::collections::hash_map::Entry::Occupied(e) => {
                    panic!(
                        "Duplicate instruction TID: {} at fn:{}:{} blk:{}:{} (first seen: fn:{}:{} blk:{}:{})",
                        insn_tid, fn_tid, fn_tid.address(), blk_tid, blk_tid.address(), e.get().0, e.get().0.address(), e.get().0, e.get().0.address()

                    );
                }
            }
        }

        assert!(self.find_wild_returns(program).1.is_empty());
        assert!(self.find_wild_branches(program).1.is_empty());
        assert!(self.find_wild_calls(program).1.is_empty());
    }
}
