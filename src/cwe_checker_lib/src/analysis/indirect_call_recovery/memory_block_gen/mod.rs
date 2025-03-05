pub mod global_block;
pub mod heap_block;
pub mod stack_block;

pub mod global_block_analysis;

use std::process::exit;

use global_block::{build_global_memory_blocks, GlobalMemorySeperation};
use global_block_analysis::foo;
use heap_block::{build_heap_blocks, HeapAnalysis};
use stack_block::{build_stack_block, StackBlockBoundaries};

use crate::{
    analysis::pointer_inference::Config, intermediate_representation::{Program, Project},
    prelude::AnalysisResults,
};

pub struct BlockMemoryModel {
    pub heap: HeapAnalysis,
    pub global: GlobalMemorySeperation,
    pub stack: StackBlockBoundaries,
}

pub fn build_memory_blocks(
    ssa_program: &Program,
    project: &Project,
    analysis: &AnalysisResults,
    config: &Config,
) -> BlockMemoryModel {
    let global_analysis = foo(ssa_program, &project.runtime_memory_image);
    let stack_boundaries = build_stack_block(ssa_program);
    println!("Stack Boundaries: {}", stack_boundaries);
    let global_boundaries = build_global_memory_blocks(
        ssa_program,
        &global_analysis
        //analysis
        //    .pointer_inference
        //    .expect("Pointer Interference is needed for BPA"),
    );
    let heap_analysis = build_heap_blocks(ssa_program, config);

    BlockMemoryModel {
        heap: heap_analysis,
        global: global_boundaries,
        stack: stack_boundaries,
    }
}
