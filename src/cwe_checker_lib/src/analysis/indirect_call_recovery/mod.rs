//! Indirect Call Target recovery, inspired by BPA.

use std::process::exit;

use crate::{
    ghidra_pcode::ir_passes::IrPass,
    intermediate_representation::{ir_passes::SingleStaticAssigment, Project},
    prelude::AnalysisResults,
    run_ir_pass,
    utils::debug,
};

pub mod memory_block_gen;
use function_taken::get_at_functions;
use memory_block_gen::build_memory_blocks;
use value_tracking::ValueTracking;

use super::pointer_inference::Config;

pub mod function_taken;
pub mod value_tracking;

/// Needs pointer interference
pub fn run_icall_recovery(
    project: &Project,
    analysis_results: &AnalysisResults,
    debug_settings: &debug::Settings,
    config: &serde_json::Value,
) {
    println!("Starting SSA");
    let mut ssa_program = project.program.clone();

    let config: Config = serde_json::from_value(config.clone()).unwrap();
    let mut pass = <SingleStaticAssigment>::new(&project);
    pass.run(&mut ssa_program);

    println!("Building Block mem");
    let block_memory_model = build_memory_blocks(&ssa_program, &analysis_results, &config);
    println!("Get AT funcs");
    let at_functions = get_at_functions(project);

    println!("Start Value Tracking");
    let value_tracking = ValueTracking::new(
        &ssa_program,
        &block_memory_model,
        &at_functions,
        &pass.active_var_at_end_of_block,
    );

    if debug_settings.should_debug(debug::Stage::ICallRec) {
        exit(0);
    }
}
