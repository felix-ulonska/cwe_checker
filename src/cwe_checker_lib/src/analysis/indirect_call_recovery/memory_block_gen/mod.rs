pub mod stack_block;

use stack_block::build_stack_block;

use crate::intermediate_representation::Program;

pub fn build_memory_blocks(program: &Program) {
    build_stack_block(program);
}
