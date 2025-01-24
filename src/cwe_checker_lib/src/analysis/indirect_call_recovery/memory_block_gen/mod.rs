pub mod stack_block;
pub mod global_block;

use global_block::build_global_memory_blocks;
use stack_block::build_stack_block;

use crate::{intermediate_representation::Program, prelude::AnalysisResults};

pub fn build_memory_blocks(program: &Program, analysis: &AnalysisResults) {
    let stack_boundaries = build_stack_block(program);
    build_global_memory_blocks(program, analysis.pointer_inference.expect("Pointer Interference is needed for BPA"));

    println!("{}", stack_boundaries);
}
