pub mod stack_block;
pub mod global_block;
pub mod heap_block;

use global_block::{build_global_memory_blocks, GlobalMemorySeperation};
use heap_block::{build_heap_blocks, HeapAnalysis};
use stack_block::{build_stack_block, StackBlockBoundaries};

use crate::{analysis::pointer_inference::Config, intermediate_representation::Program, prelude::AnalysisResults};

pub struct BlockMemoryModel {
    pub heap: HeapAnalysis,
    pub global: GlobalMemorySeperation,
    pub stack: StackBlockBoundaries,
}

pub fn build_memory_blocks(program: &Program, analysis: &AnalysisResults, config: &Config) -> BlockMemoryModel {
    let stack_boundaries = build_stack_block(program);
    let global_boundaries = build_global_memory_blocks(program, analysis.pointer_inference.expect("Pointer Interference is needed for BPA"));
    let heap_analysis = build_heap_blocks(program, config);

    BlockMemoryModel {
        heap: heap_analysis,
        global: global_boundaries,
        stack: stack_boundaries
    }
}
