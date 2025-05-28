use std::{collections::{HashMap, HashSet}, env};

use ascent::rayon::{
    iter::{IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator},
    slice::ParallelSlice,
};
use itertools::Itertools;

use crate::{
    intermediate_representation::{
        ir_passes::{VarsAtEndOfBlock, SPLIT_SYMBOL},
        CallingConvention, Def, Expression, Jmp, Program, Variable,
    },
    prelude::Tid,
};

/// Slice the **SSA** program, so that only assigments and variables exist that
/// 1) Are used as inputs to Store instructions
/// 2) Are used as index for Store (a) and Load (b) Instructions
/// 3) Are at the end of a block with a call instruction.
/// 4) Are at the beginning of a function
/// 5) Are at a block which is targeted by a return
///
/// Phi function are not deleted if:
/// 1) beginning of a function
/// 2) At a block which can be returtned to
/// Works inplace
/// Returns a rename table
pub fn slice_program(
    ssa_program: &mut Program,
    var_at_end_of_block: &VarsAtEndOfBlock,
    calling_convention: &CallingConvention,
) -> HashMap<Variable, Variable> {
    let blocks_with_full_phi = build_blocks_without_changes(ssa_program, calling_convention);
    eprintln!("Removing unused Instructions");
    let rename_table = if env::var("CWE_CHECKER_PROFILING_DISBALE_EXPRESSION").is_ok() {
        eprintln!("SKIPPING expression propagation");
        println!("SKIPPING expression propagation");
        HashMap::new()
    } else {
        remove_unused_instructions(ssa_program, &blocks_with_full_phi)
    };

    if env::var("CWE_CHECKER_PROFILING_DISBALE_SLICING").is_ok() {
        eprintln!("SKIPPING taint analysis");
        println!("SKIPPING taint analysis");
    } else {
        eprintln!("Start taint analysis");
        let tainted_vars = taint(ssa_program, var_at_end_of_block, &blocks_with_full_phi);
        eprintln!("Remove Instruction WIthout taint");
        remove_instructions_without_tainted_vars(ssa_program, tainted_vars);
    }

    rename_table
}

fn remove_instructions_without_tainted_vars(
    ssa_program: &mut Program,
    tained_var: HashSet<Variable>,
) {
    for blk in ssa_program.blocks_mut() {
        blk.defs = blk
            .defs
            .iter()
            .filter(|def| {
                for input_var in def.used_vars() {
                    if tained_var.contains(input_var) {
                        return true;
                    }
                }
                if let Def::Store { .. } | Def::Load { .. } = def.term {
                    return true;
                }
                return false;
            })
            .map(|def| def.clone())
            .collect_vec();
    }
}

// A -> B
// B -> C
// C -> D
// B -> D
//
// Changes HashMap to this:
//
// A -> D
// b -> D
// c -> D
// B -> D
fn remove_intermediate_steps(input: &mut HashMap<Variable, Variable>) {
    let keys: Vec<_> = input.keys().cloned().collect();

    eprintln!("Has renamed {} variables", input.len());
    let input_size = input.len();
    let updates = keys
        .par_chunks(1000)
        .map(|chunk| {
            let mut local_map = HashMap::with_capacity(chunk.len());

            for key in chunk {
                let mut next = input.get(key);

                let mut i = 0;
                while let Some(val) = next.and_then(|k| input.get(k)) {
                    if i > input_size {
                        panic!("remove_intermediate_steps has a circular rename");
                    }
                    next = Some(val);
                    i += 1;
                }

                if let Some(final_val) = next {
                    local_map.insert(key.clone(), final_val.clone());
                }
            }

            local_map
        })
        .reduce(
            || HashMap::new(),
            |mut acc, map| {
                acc.extend(map);
                acc
            },
        );

    input.extend(updates);
}

struct SpecialBlocks {
    returned_to_blocks: HashSet<Tid>,
    return_blocks: HashSet<Tid>,
    called_blocks: HashSet<Tid>,
    calling_convention: CallingConvention,
}

impl SpecialBlocks {
    fn is_ssa_var_ret_reg(&self, var: &Variable) -> bool {
        self.calling_convention
            .get_all_return_register()
            .iter()
            .any(|ret_var| var.name.contains(&ret_var.name))
    }

    fn is_ssa_var_callee_saved(&self, var: &Variable) -> bool {
        self.calling_convention
            .callee_saved_register
            .iter()
            .any(|ret_var| var.name.contains(&ret_var.name))
    }

    fn is_ssa_var_param(&self, var: &Variable) -> bool {
        self.calling_convention
            .get_all_parameter_register()
            .iter()
            .any(|ret_var| var.name.contains(&ret_var.name))
    }
}

fn build_blocks_without_changes(
    ssa_program: &Program,
    calling_convention: &CallingConvention,
) -> SpecialBlocks {
    // Blocks where phi functions are not shorted
    let mut return_blocks = HashSet::new();
    let mut returned_to_blocks = HashSet::new();

    // Fill block_with_full_phi for blocks in which no optimization are done
    for blk in ssa_program.blocks() {
        for jmp in blk.jmps() {
            if let Jmp::CallInd { return_, .. } = &jmp.term {
                if let Some(return_) = return_ {
                    returned_to_blocks.insert(return_.clone());
                }
            }
            if let Jmp::Return { .. } = &jmp.term {
                return_blocks.insert(blk.tid.clone());
            }
        }
    }

    let called_blocks = ssa_program
        .subs
        .par_iter()
        .map(|sub| {
            let first_block = sub.1.blocks().take(1).next().unwrap();
            first_block.tid.clone()
        })
        .collect::<std::collections::HashSet<_>>();

    SpecialBlocks {
        called_blocks,
        returned_to_blocks,
        return_blocks,
        calling_convention: calling_convention.clone(),
    }
}

// Essentially the Dead Var eliminiation with some extra rules
// All Assigments with one input var, get inlined. That should be the phi instructions
fn remove_unused_instructions(
    ssa_program: &mut Program,
    special_blocks: &SpecialBlocks,
) -> HashMap<Variable, Variable> {

    let mut local_rename_table = HashMap::new();
    let mut def_to_remove = HashSet::new();
    // rename First to Second Element
    ssa_program
        .blocks_mut()
        .collect_vec()
        .iter_mut()
        .for_each(|blk| {
            // Skip blocks which can be returnted to or are at the start of a function.

            for def in blk.defs() {
                if let Def::Assign { var, value } = &def.term {
                    if special_blocks.returned_to_blocks.contains(&blk.tid)
                        && (special_blocks.is_ssa_var_ret_reg(var)
                            || special_blocks.is_ssa_var_callee_saved(var))
                    {
                        continue;
                    }

                    if special_blocks.called_blocks.contains(&blk.tid)
                        && special_blocks.is_ssa_var_param(var)
                    {
                        continue;
                    }
                    let inputs = value.input_vars();
                    // Single Input var: Can be replaced with original value
                    // Phi instruction can have the same input as output if within a loop; do not
                    // change
                    if inputs.len() == 1 {
                        // On PowerPC xer_so sneak into the phi registers: we skip that
                        if inputs[0] == var || inputs[0].name == "xer_so" {
                            continue;
                        }
                        // If loops exist there could recursion. If the new variable has a lower
                        // index, it indicates that we have loop backedge. Skip those variables
                        // This could like this:
                        // x_1 := x_2
                        // x_2 := x_1
                        // Without this check, we would have a loop x_1 => x_2 => x_1...
                        // We break the loop because we do not rename the first statement
                        if inputs[0]
                            .name
                            .split_once(SPLIT_SYMBOL)
                            .unwrap()
                            .1
                            .parse::<i32>()
                            .ok()
                            .unwrap()
                            > var
                                .name
                                .split_once(SPLIT_SYMBOL)
                                .unwrap()
                                .1
                                .parse::<i32>()
                                .ok()
                                .unwrap()
                        {
                            continue;
                        }
                        local_rename_table.insert(var.clone(), inputs[0].clone());
                        def_to_remove.insert(def.tid.clone());
                    }
                }
            }
            blk.defs = blk
                .defs
                .iter()
                .filter(|def| !def_to_remove.contains(&def.tid))
                .map(|def| def.clone())
                .collect_vec();
            ()
        });
    remove_intermediate_steps(&mut local_rename_table);

    let rename_table_clone = local_rename_table.clone();
    let rename_table_keys: HashSet<&Variable> = HashSet::from_iter(rename_table_clone.keys());

    // This is quadratic runtime!
    // Replace all vars until no variable is left from the rename_table is needed
    ssa_program
        .blocks_mut()
        .collect_vec()
        .par_iter_mut()
        .for_each(|blk| {
            let mut changed = true;
            let mut iter = 0;
            // Change mechanism probably not needed here
            while changed {
                iter += 1;
                if iter > 10000 {
                    panic!("Loop did not settle");
                }
                changed = false;
                for def in blk.defs_mut() {
                    let cloned_def = def.clone();
                    let used_vars: HashSet<&Variable> =
                        HashSet::from_iter(cloned_def.inputs_vars());
                    let used_old_vars = rename_table_keys.intersection(&used_vars);

                    for old_var in used_old_vars {
                        let new_variable = local_rename_table.get(*old_var).unwrap();
                        if new_variable == *old_var {
                            continue;
                        }
                        let new_expr = &Expression::Var((*new_variable).clone());
                        changed = true;
                        def.substitute_input_var(old_var, new_expr);
                    }
                }
                for jmp in blk.jmps_mut() {
                    let Jmp::CallInd { target, .. } = jmp.term.clone() else {
                        continue;
                    };
                    let used_vars: HashSet<&Variable> = HashSet::from_iter(target.input_vars());
                    let used_old_vars = rename_table_keys.intersection(&used_vars);

                    for old_var in used_old_vars {
                        let new_variable = local_rename_table.get(*old_var).unwrap();
                        let new_expr = &Expression::Var((*new_variable).clone());
                        if new_variable == *old_var {
                            continue;
                        }
                        changed = true;
                        jmp.substitute_input_var(old_var, new_expr);
                    }
                }
            }
        });

    local_rename_table
}

fn taint<'a>(
    program: &'a Program,
    var_at_end_of_block: &VarsAtEndOfBlock,
    special_blocks: &SpecialBlocks,
) -> HashSet<Variable> {
    let mut changes = true;
    let mut taint: HashSet<&Variable> = HashSet::new();
    let mut checked = HashSet::new();

    for blk in program.blocks() {
        for def in blk.defs() {
            match &def.term {
                crate::intermediate_representation::Def::Load { address, .. } => {
                    // Case 2b
                    taint.extend(address.input_vars());
                }
                crate::intermediate_representation::Def::Store { address, value } => {
                    // Case 2a
                    taint.extend(address.input_vars());
                    // Case 1
                    taint.extend(value.input_vars());
                }
                _ => (),
            }
        }

        for jmp in blk.jmps() {
            if let Jmp::CallInd { target, .. } = &jmp.term {
                // Case 3
                taint.extend(target.input_vars());
                taint.extend(HashSet::<&Variable>::from_iter(
                    var_at_end_of_block
                        .get(&blk.tid)
                        .unwrap()
                        .iter()
                        .filter(|var| special_blocks.is_ssa_var_param(var)),
                ));
            }
            if let Jmp::Return { .. } = &jmp.term {
                // Case 5
                taint.extend(HashSet::<&Variable>::from_iter(
                    var_at_end_of_block
                        .get(&blk.tid)
                        .unwrap()
                        .iter()
                        .filter(|var| special_blocks.is_ssa_var_ret_reg(var)),
                ));
            }
        }
    }

    while changes {
        changes = false;

        for blk in program.blocks() {
            for def in blk.defs() {
                if checked.contains(&def.tid) {
                    continue;
                }
                if let Def::Assign { var, value } = &def.term {
                    if taint.contains(&var) {
                        checked.insert(def.tid.clone());
                        changes = true;
                        taint.extend(value.input_vars());
                    }
                }
            }
        }
    }

    HashSet::from_iter(taint.iter().map(|var| (*var).clone()))
}
