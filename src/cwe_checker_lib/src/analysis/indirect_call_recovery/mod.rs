//! Indirect Call Target recovery, inspired by BPA.

use std::process::exit;

use crate::{ghidra_pcode::ir_passes::IrPass, intermediate_representation::{ir_passes::SingleStaticAssigment, Project}, prelude::AnalysisResults, run_ir_pass, utils::debug};

pub mod memory_block_gen;
use memory_block_gen::build_memory_blocks;

/// Needs pointer interference
pub fn run_icall_recovery(project: &Project, analysis_results: &AnalysisResults, debug_settings: &debug::Settings) {
    let mut ssa_program = project.program.clone();
    let mut logs = Vec::new();

    run_ir_pass![
        ssa_program,
        project,
        SingleStaticAssigment,
        logs,
        debug_settings,
    ];

    build_memory_blocks(&ssa_program, &analysis_results);

    if debug_settings.should_debug(debug::Stage::ICallRec) {
        exit(0);
    }
}
