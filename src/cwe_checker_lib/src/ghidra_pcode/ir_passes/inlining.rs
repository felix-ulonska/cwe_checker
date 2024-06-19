use super::prelude::*;
use crate::intermediate_representation::{
    Blk as IrBlk, Jmp as IrJmp, Program as IrProgram, Term as IrTerm, Tid,
};

use std::collections::{BTreeMap, BTreeSet};

/// Inline blocks shared between functions.
///
/// - For each function `f`, this pass (recursively) discovers all blocks
///   outside of `f` that are reachable (via intraprocedural CFTs) from blocks
///   within it.
/// - It duplicates and inlines these blocks into `f`.
///
/// # Postconditions
///
/// 1. Every function `f` is closed under the operation of following all
///    intraprocedural references in its blocks. Excluding references whose
///    target is not existing within the program.
///
/// # Run After
pub struct InliningPass {
    tid_to_fn_tid_map: BTreeMap<Tid, Tid>,
}

impl IrPass for InliningPass {
    const NAME: &'static str = "InliningPass";
    const DBG_IR_FORM: debug::IrForm = debug::IrForm::Inlined;

    type Input = Program;
    type ConstructionInput = Self::Input;

    fn new(program: &Self::ConstructionInput) -> Self {
        Self {
            tid_to_fn_tid_map: Self::generate_tid_to_fn_tid_map(program),
        }
    }

    fn run(&mut self, program: &mut Self::Input) -> Vec<LogMessage> {
        let mut logs = Vec::new();

        let blk_tid_to_blk_term_map = Self::generate_blk_tid_to_blk_term_map(program);
        let fn_tid_to_blk_tids_map =
            self.generate_fn_tid_to_blk_tids_map(program, &blk_tid_to_blk_term_map);
        let mut fn_tid_to_add_blks_map = self.generate_fn_tid_to_add_blks_map(
            program,
            &fn_tid_to_blk_tids_map,
            &blk_tid_to_blk_term_map,
        );

        for f in program.functions_mut() {
            let mut additional_blocks = fn_tid_to_add_blks_map.remove(&f.tid).unwrap();

            for msg in additional_blocks.iter().map(|b| {
                LogMessage::new_info(format!(
                    "{}: Block '{}' inlined into function '{}'.",
                    Self::NAME,
                    b.tid,
                    f.tid
                ))
            }) {
                logs.push(msg);
            }

            f.term.blocks.append(&mut additional_blocks);
        }

        assert!(fn_tid_to_add_blks_map.is_empty());

        self.append_jump_targets_with_fn_suffix_when_target_block_was_duplicated(program);

        logs
    }

    fn assert_postconditions(construction_input: &Self::ConstructionInput, program: &Self::Input) {
        let pass = Self::new(construction_input);

        // 1. Every function `f` is closed under the operation of following all
        //    intraprocedural references in its blocks. Excluding references
        //    whose target is not existing within the program.
        let blk_tid_to_blk_term_map = Self::generate_blk_tid_to_blk_term_map(program);
        let fn_tid_to_blk_tids_map =
            pass.generate_fn_tid_to_blk_tids_map(program, &blk_tid_to_blk_term_map);
        let fn_tid_to_add_blks_map = pass.generate_fn_tid_to_add_blks_map(
            program,
            &fn_tid_to_blk_tids_map,
            &blk_tid_to_blk_term_map,
        );

        for (fn_tid, add_blks) in fn_tid_to_add_blks_map.iter() {
            assert!(
                add_blks.is_empty(),
                "Function '{}' not closed after inlining pass.",
                fn_tid
            );
        }
    }
}

impl InliningPass {
    /// Returns true iff both TIDs exist in the original program and belong to
    /// the same function.
    fn originally_in_same_fn(&self, tid1: &Tid, tid2: &Tid) -> bool {
        match (
            self.tid_to_fn_tid_map.get(tid1),
            self.tid_to_fn_tid_map.get(tid2),
        ) {
            (Some(fn_of_tid1), Some(fn_of_tid2)) => fn_of_tid1 == fn_of_tid2,
            _ => false,
        }
    }

    /// Appends the `Sub` TID to targets of intraprocedural jumps
    /// if the target block was inlined (such that the jumps target the correct
    /// blocks again).
    fn append_jump_targets_with_fn_suffix_when_target_block_was_duplicated(
        &self,
        program: &mut IrProgram,
    ) {
        for f in program.functions_mut() {
            let fn_tid_suffix = f.id_suffix();
            let fn_tid = f.tid.clone();
            for b in f.blocks_mut() {
                for j in b.jmps_mut() {
                    match &mut j.term {
                        IrJmp::Branch(target)
                        | IrJmp::CBranch { target, .. }
                        | IrJmp::Call {
                            return_: Some(target),
                            ..
                        }
                        | IrJmp::CallInd {
                            return_: Some(target),
                            ..
                        }
                        | IrJmp::CallOther {
                            return_: Some(target),
                            ..
                        } if !self.originally_in_same_fn(&fn_tid, target) => {
                            *target = target.clone().with_id_suffix(&fn_tid_suffix);
                        }
                        _ => (),
                    }
                }
                // Adjust indirect jump targets that will be inlined.
                if let Some(indirect_jump_targets_iter) = b.term.ind_jump_targets_targets_mut() {
                    for target in indirect_jump_targets_iter
                        .filter(|target| !self.originally_in_same_fn(&fn_tid, target))
                    {
                        *target = target.clone().with_id_suffix(&fn_tid_suffix);
                    }
                }
            }
        }
    }

    /// Create duplicates of blocks that are reachable from the blocks
    /// originally present in a function.
    ///
    /// The TIDs of the newly created blocks and the contained Defs and Jmps are
    /// appended with the TID of the sub they are contained in (to ensure that
    /// the newly created terms have unique TIDs).
    ///
    /// The TIDs of jump and return targets are not adjusted in this function.
    /// The returned map maps the TID of a `Sub` to the newly created blocks
    /// for that `Sub`.
    fn generate_fn_tid_to_add_blks_map(
        &self,
        program: &IrProgram,
        fn_tid_to_blk_tids_map: &BTreeMap<Tid, BTreeSet<Tid>>,
        blk_tid_to_block_term_map: &BTreeMap<Tid, &IrTerm<IrBlk>>,
    ) -> BTreeMap<Tid, Vec<IrTerm<IrBlk>>> {
        program
            .functions()
            .map(|f| {
                let tid_suffix = f.id_suffix();
                let additional_blocks = fn_tid_to_blk_tids_map
                    .get(&f.tid)
                    .unwrap()
                    .iter()
                    .filter_map(|blk_tid| {
                        if self.tid_to_fn_tid_map.get(blk_tid).unwrap() != &f.tid {
                            Some(
                                blk_tid_to_block_term_map
                                    .get(blk_tid)
                                    .unwrap()
                                    .clone_with_tid_suffix(&tid_suffix),
                            )
                        } else {
                            None
                        }
                    })
                    .collect();

                (f.tid.clone(), additional_blocks)
            })
            .collect()
    }

    /// Returns a map from all `Sub`, `Blk`, `Def` and `Jmp` TIDs of the
    /// program to the `Sub` TID in which the term is contained.
    fn generate_tid_to_fn_tid_map(program: &IrProgram) -> BTreeMap<Tid, Tid> {
        let mut tid_to_fn_tid_map = BTreeMap::new();

        for f in program.functions() {
            tid_to_fn_tid_map.insert(f.tid.clone(), f.tid.clone());
            for b in f.blocks() {
                tid_to_fn_tid_map.insert(b.tid.clone(), f.tid.clone());
                for d in b.defs() {
                    tid_to_fn_tid_map.insert(d.tid.clone(), f.tid.clone());
                }
                for j in b.jmps() {
                    tid_to_fn_tid_map.insert(j.tid.clone(), f.tid.clone());
                }
            }
        }

        tid_to_fn_tid_map
    }

    /// Returns a map that maps all block TIDs to the corresponding block term.
    fn generate_blk_tid_to_blk_term_map(program: &IrProgram) -> BTreeMap<Tid, &IrTerm<IrBlk>> {
        program
            .functions()
            .flat_map(|f| f.blocks().map(|b| (b.tid.clone(), b)))
            .collect()
    }

    /// If the jump is intraprocedural, return its target TID.
    /// If the jump is a call, return the TID of the return target.
    ///
    /// Only returns TIDs that actually exist within the program.
    fn get_intraprocedural_target_or_return_block_tid(&self, jmp: &IrJmp) -> Option<Tid> {
        match jmp {
            IrJmp::Branch(target)
            | IrJmp::CBranch { target, .. }
            | IrJmp::Call {
                return_: Some(target),
                ..
            }
            | IrJmp::CallInd {
                return_: Some(target),
                ..
            }
            | IrJmp::CallOther {
                return_: Some(target),
                ..
            } if self.tid_to_fn_tid_map.contains_key(target) => {
                debug_assert!(
                    target.is_block()
                        || target.is_artificial_sink_block()
                        || target.is_artificial_return_target_block(),
                    "Not a block: {}",
                    target
                );

                Some(target.clone())
            }
            _ => None,
        }
    }

    /// Returns a map from all `Sub` TIDs to the set of all block TIDs
    /// that are either initially present in the function or reachable from
    /// blocks that are initially present in the function.
    fn generate_fn_tid_to_blk_tids_map(
        &self,
        program: &IrProgram,
        blk_tid_to_blk_term_map: &BTreeMap<Tid, &IrTerm<IrBlk>>,
    ) -> BTreeMap<Tid, BTreeSet<Tid>> {
        let mut fn_tid_to_block_tids_map = BTreeMap::new();
        for f in program.functions() {
            let mut worklist: Vec<Tid> = f.blocks().map(|b| b.tid.clone()).collect();
            let mut block_set = BTreeSet::new();
            while let Some(block_tid) = worklist.pop() {
                if block_set.contains(&block_tid) {
                    continue;
                } else {
                    block_set.insert(block_tid.clone());
                }

                let block = blk_tid_to_blk_term_map.get(&block_tid).unwrap();
                worklist.extend(block.jmps().filter_map(|j| {
                    match self.get_intraprocedural_target_or_return_block_tid(j) {
                        Some(tid) if !block_set.contains(&tid) => Some(tid),
                        _ => None,
                    }
                }));
                if let Some(indirect_jump_targets) = block.ind_jump_targets() {
                    worklist.extend(indirect_jump_targets.filter_map(|target_tid| {
                        if !block_set.contains(target_tid)
                            && self.tid_to_fn_tid_map.contains_key(target_tid)
                            && target_tid.is_block()
                        {
                            Some(target_tid.clone())
                        } else {
                            None
                        }
                    }));
                }
            }
            fn_tid_to_block_tids_map.insert(f.tid.clone(), block_set);
        }

        fn_tid_to_block_tids_map
    }
}

/// TODO: Fix tests.
#[cfg(test)]
mod tests {
    use super::*;
    use std::iter::FromIterator;

    fn create_block_with_jump_target(block_name: &str, target_name: &str) -> Term<Blk> {
        Term {
            tid: Tid::new(block_name),
            term: Blk {
                defs: Vec::new(),
                jmps: vec![Term {
                    tid: Tid::new(format!("jmp_{}", block_name)),
                    term: Jmp::Branch(Tid::new(target_name)),
                }],
                indirect_jmp_targets: Vec::new(),
            },
        }
    }

    fn create_sub_with_blocks(sub_name: &str, blocks: Vec<Term<Blk>>) -> Term<Sub> {
        Term {
            tid: Tid::new(sub_name),
            term: Sub {
                name: sub_name.to_string(),
                blocks,
                calling_convention: None,
            },
        }
    }

    #[test]
    fn duplication_of_blocks_contained_in_several_subs() {
        let sub_1 = create_sub_with_blocks(
            "sub_1",
            vec![
                create_block_with_jump_target("blk_1", "blk_2"),
                create_block_with_jump_target("blk_2", "blk_1"),
            ],
        );
        let sub_2 = create_sub_with_blocks(
            "sub_2",
            vec![create_block_with_jump_target("blk_3", "blk_2")],
        );
        let sub_3 = create_sub_with_blocks(
            "sub_3",
            vec![create_block_with_jump_target("blk_4", "blk_3")],
        );
        let sub_1_tid = &sub_1.tid;
        let sub_2_tid = &sub_2.tid;
        let sub_3_tid = &sub_3.tid;
        let mut project = Project::mock_x64();
        project.program.term.subs = BTreeMap::from_iter([
            (sub_1_tid.clone(), sub_1.clone()),
            (sub_2_tid.clone(), sub_2.clone()),
            (sub_3.tid.clone(), sub_3.clone()),
        ]);

        make_block_to_sub_mapping_unique(&mut project);

        assert_eq!(&project.program.term.subs[sub_1_tid], &sub_1);
        let sub_2_modified = create_sub_with_blocks(
            "sub_2",
            vec![
                create_block_with_jump_target("blk_3", "blk_2_sub_2"),
                create_block_with_jump_target("blk_2_sub_2", "blk_1_sub_2"),
                create_block_with_jump_target("blk_1_sub_2", "blk_2_sub_2"),
            ],
        );
        assert_eq!(project.program.term.subs[sub_2_tid].term.blocks.len(), 3);
        assert_eq!(
            &project.program.term.subs[sub_2_tid].term.blocks[0],
            &sub_2_modified.term.blocks[0]
        );
        assert!(project.program.term.subs[sub_2_tid]
            .term
            .blocks
            .contains(&sub_2_modified.term.blocks[1]));
        assert!(project.program.term.subs[sub_2_tid]
            .term
            .blocks
            .contains(&sub_2_modified.term.blocks[2]));
        let sub_3_modified = create_sub_with_blocks(
            "sub_3",
            vec![
                create_block_with_jump_target("blk_4", "blk_3_sub_3"),
                create_block_with_jump_target("blk_3_sub_3", "blk_2_sub_3"),
                create_block_with_jump_target("blk_2_sub_3", "blk_1_sub_3"),
                create_block_with_jump_target("blk_1_sub_3", "blk_2_sub_3"),
            ],
        );
        assert_eq!(project.program.term.subs[sub_3_tid].term.blocks.len(), 4);
        assert_eq!(
            &project.program.term.subs[sub_3_tid].term.blocks[0],
            &sub_3_modified.term.blocks[0]
        );
        assert!(project.program.term.subs[sub_3_tid]
            .term
            .blocks
            .contains(&sub_3_modified.term.blocks[0]));
        assert!(project.program.term.subs[sub_3_tid]
            .term
            .blocks
            .contains(&sub_3_modified.term.blocks[1]));
        assert!(project.program.term.subs[sub_3_tid]
            .term
            .blocks
            .contains(&sub_3_modified.term.blocks[2]));
        assert!(project.program.term.subs[sub_3_tid]
            .term
            .blocks
            .contains(&sub_3_modified.term.blocks[3]));
    }
}
