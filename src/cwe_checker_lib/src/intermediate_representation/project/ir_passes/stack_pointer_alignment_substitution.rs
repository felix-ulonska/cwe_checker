//! Substitutes stack pointer alignment operations utilising logical AND with an arithmetic SUB operation.
//!
//! The first basic block of every function is searched for a logical AND operation on the stack pointer.
//! By journaling changes to the stack pointer an offset is calculated which is going to be used to alter the operation
//! into a subtraction.
//!
//! # Log Messages
//! Following cases trigger log messages:
//! - alignment is untypical for the architecture
//! - the argument for the AND operation is not a constant
//! - an operation alters the stack pointer, which can not be journaled.
use super::prelude::*;

use crate::intermediate_representation::{Project, Variable};

mod legacy;

pub struct StackPointerAlignmentSubstitutionPass {
    stack_pointer_register: Variable,
    cpu_architecture: String,
}

impl IrPass for StackPointerAlignmentSubstitutionPass {
    const NAME: &'static str = "StackPointerAlignmentSubstitutionPass";
    const DBG_IR_FORM: debug::IrForm = debug::IrForm::StackPointerAlignmentSubstituted;

    type Input = Program;
    type ConstructionInput = Project;

    fn new(project: &Self::ConstructionInput) -> Self {
        Self {
            stack_pointer_register: project.stack_pointer_register.clone(),
            cpu_architecture: project.cpu_architecture.clone(),
        }
    }

    fn run(&mut self, program: &mut Self::Input) -> Vec<LogMessage> {
        legacy::substitute_and_on_stackpointer(program, &self.stack_pointer_register, &self.cpu_architecture)
    }

    fn assert_postconditions(_construction_input: &Self::ConstructionInput, _program: &Self::Input) {}
}
