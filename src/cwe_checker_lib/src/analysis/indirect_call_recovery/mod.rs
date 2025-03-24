//! Indirect Call Target recovery, inspired by BPA.

use std::process::exit;

use crate::{
    ghidra_pcode::ir_passes::IrPass,
    intermediate_representation::{ir_passes::SingleStaticAssigment, Program, Project},
    utils::debug,
};

pub mod memory_block_gen;
use function_taken::get_at_functions;
use itertools::Itertools;
use memory_block_gen::build_memory_blocks;
use value_tracking::{convert_to_ascent_prog::ValueTracking, slice::slice_program};

use super::pointer_inference::Config;

pub mod function_taken;
pub mod value_tracking;

fn statistics(prog: &Program) {
    let mut indirect_call_counter = 0;
    let mut instr_counter = 0;
    for blk in prog.blocks() {
        let len_defs = blk.defs().collect_vec().len();
        instr_counter += len_defs;
        for call in blk.jmps() {
            if call.is_indirect_call() {
                indirect_call_counter += 1;
            }
        }
    }
    println!("Prog has:\t {} indirect calls", indirect_call_counter);
    println!("\t {} instructions", instr_counter);
}

/// Needs pointer interference
pub fn run_icall_recovery(
    project: &Project,
    debug_settings: &debug::Settings,
    config: &serde_json::Value,
) {
    println!("Starting SSA");
    let mut ssa_program = project.program.clone();

    let config: Config = serde_json::from_value(config.clone()).unwrap();
    let mut pass = <SingleStaticAssigment>::new(&project);
    pass.run(&mut ssa_program);

    println!("Building Block mem");
    let block_memory_model = build_memory_blocks(&ssa_program, &project, &config);
    println!("Get AT funcs");
    let at_functions = get_at_functions(project);

    let mut sliced_program = ssa_program.clone();
    statistics(&ssa_program);
    let rename_table = slice_program(&mut sliced_program, &pass.active_var_at_end_of_block);
    ssa_program = sliced_program;
    statistics(&ssa_program);

    println!("Start Value Tracking");
    let mut value_tracking = ValueTracking::new(
        &ssa_program,
        &block_memory_model,
        &at_functions,
        &pass.active_var_at_end_of_block,
        &rename_table,
    );

    value_tracking.run_value_tracking();

    if debug_settings.should_debug(debug::Stage::ICallRec) {
        exit(0);
    }
}
