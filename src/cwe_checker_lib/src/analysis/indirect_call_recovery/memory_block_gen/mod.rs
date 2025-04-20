pub mod global_block;
pub mod heap_block;
pub mod stack_block;

pub mod global_block_analysis;

use std::time::Instant;

use global_block::{build_global_memory_blocks, GlobalMemorySeperation};
use global_block_analysis::infer_global_ptr;
use heap_block::{build_heap_blocks, HeapAnalysis};
use stack_block::{build_stack_block, StackBlockBoundaries};

use crate::{
    analysis::pointer_inference::Config,
    intermediate_representation::{Program, Project},
    prelude::ByteSize,
};

pub struct BlockMemoryModel {
    pub heap: HeapAnalysis,
    pub global: GlobalMemorySeperation,
    pub stack: StackBlockBoundaries,
}

pub fn build_memory_blocks(
    ssa_program: &Program,
    project: &Project,
    config: &Config,
) -> BlockMemoryModel {
    let mut start_time = Instant::now();
    let global_analysis = infer_global_ptr(
        ssa_program,
        &project.runtime_memory_image,
        //project.register_set.first().unwrap().size,
        ByteSize::new(8),
    );
    eprintln!(
        "Finished Global Analysis within: {:02?}",
        start_time.elapsed()
    );
    start_time = Instant::now();
    let global_boundaries = build_global_memory_blocks(
        ssa_program,
        &global_analysis, //analysis
                          //    .pointer_inference
                          //    .expect("Pointer Interference is needed for BPA"),
    );
    eprintln!(
        "Finished Global Block Analysis within: {:02?}",
        start_time.elapsed()
    );
    start_time = Instant::now();
    let stack_boundaries = build_stack_block(ssa_program);
    eprintln!(
        "Finished Stack Block Analysis within: {:02?}",
        start_time.elapsed()
    );
    start_time = Instant::now();
    let heap_analysis = build_heap_blocks(ssa_program, config);
    eprintln!(
        "Finished Heap Analysis within: {:02?}",
        start_time.elapsed()
    );

    BlockMemoryModel {
        heap: heap_analysis,
        global: global_boundaries,
        stack: stack_boundaries,
    }
}
