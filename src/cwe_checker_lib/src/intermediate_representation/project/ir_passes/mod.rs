mod control_flow_propagation;
pub use control_flow_propagation::*;

mod dead_variable_elim;
pub use dead_variable_elim::*;

mod intraprocedural_dead_block_elim;
pub use intraprocedural_dead_block_elim::*;

mod stack_pointer_alignment_substitution;
pub use stack_pointer_alignment_substitution::*;

mod trivial_expression_substitution;
pub use trivial_expression_substitution::*;

mod input_expression_propagation;
pub use input_expression_propagation::*;

pub use crate::ghidra_pcode::ir_passes::prelude;
pub use crate::ghidra_pcode::ir_passes::{debug_assert_postconditions, run_ir_pass, IrPass};
