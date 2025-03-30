//! Indirect Call Target recovery, inspired by BPA.
pub mod json_export;

use std::process::exit;

use crate::{
    ghidra_pcode::ir_passes::IrPass,
    intermediate_representation::{ir_passes::SingleStaticAssigment, Program, Project},
    utils::debug,
};

pub mod memory_block_gen;
use function_taken::get_at_functions;
use itertools::Itertools;
use json_export::export_json;
use memory_block_gen::build_memory_blocks;
use value_tracking::{
    convert_to_ascent_prog::ValueTracking, output::IndirectCalls, slice::slice_program,
    AscentProgram,
};

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

// Helper method to drop all structs information that is only constructed to build the ascent_prog
fn build_ascent_prog(
    project: &Project,
    debug_settings: &debug::Settings,
    config: &serde_json::Value,
) -> AscentProgram {
    eprintln!("Starting SSA");
    let mut ssa_program = project.program.clone();

    let config: Config = serde_json::from_value(config.clone()).unwrap();
    let mut pass = <SingleStaticAssigment>::new(&project);
    pass.run(&mut ssa_program);

    eprintln!("Building Block mem");
    let block_memory_model = build_memory_blocks(&ssa_program, &project, &config);
    eprintln!("Get AT funcs");
    let at_functions = get_at_functions(project);

    let mut sliced_program = ssa_program.clone();
    statistics(&ssa_program);
    let rename_table = slice_program(&mut sliced_program, &pass.active_var_at_end_of_block);
    ssa_program = sliced_program;
    //statistics(&ssa_program);

    eprintln!("Start Value Tracking");
    let mut value_tracking = ValueTracking::new(
        &ssa_program,
        &block_memory_model,
        &at_functions,
        &pass.active_var_at_end_of_block,
        &rename_table,
    );
    // Run inside here, to get debug logs. Run outside to drop the helper structs which were used
    // to built the ascent_prog
    value_tracking.convert();
    if debug_settings.should_debug(debug::Stage::ICallRec(true)) {
        value_tracking.run_value_tracking_with_debug();
    }

    let ValueTracking { ascent_prog, .. } = value_tracking;
    ascent_prog
}

/// Needs pointer interference
pub fn run_icall_recovery(
    project: &mut Project,
    debug_settings: &debug::Settings,
    config: &serde_json::Value,
) {
    //value_tracking.run_value_tracking();
    let mut ascent_prog = build_ascent_prog(project, debug_settings, config);
    // Run this, if the ascent_prog is not already run in the build_ascent_prog. This is done to
    // drop all the helper structs to build the prog.
    if !debug_settings.should_debug(debug::Stage::ICallRec(true)) {
        ascent_prog.run();
    }
    let indirect_calls = IndirectCalls::from_ascent_prog(&mut ascent_prog);
    indirect_calls.add_to_program(&mut project.program);
    println!("{}", ascent_prog.scc_times_summary());

    if debug_settings.should_debug(debug::Stage::ICallRec(false))
        || debug_settings.should_debug(debug::Stage::ICallRec(true))
    {
        export_json(&project.program);
        exit(0);
    }
}
