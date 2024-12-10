use super::prelude::*;
use crate::intermediate_representation::{Def, Jmp};

/// For all expressions contained in the project, replace trivially computable
/// subexpressions like `a XOR a` with their result.
pub struct TrivialExpressionSubstitutionPass;

impl IrPass for TrivialExpressionSubstitutionPass {
    const NAME: &'static str = "TrivialExpressionSubstitutionPass";
    const DBG_IR_FORM: debug::IrForm = debug::IrForm::TrivialExpressionsSubstituted;

    type Input = Program;
    type ConstructionInput = ();

    fn new(_construction_input: &Self::ConstructionInput) -> Self {
        Self
    }

    fn run(&mut self, program: &mut Self::Input) -> Vec<LogMessage> {
        for block in program.blocks_mut() {
            for def in block.defs_mut() {
                match &mut def.term {
                    Def::Assign { value: expr, .. } | Def::Load { address: expr, .. } => {
                        expr.substitute_trivial_operations()
                    }
                    Def::Store { address, value } => {
                        address.substitute_trivial_operations();
                        value.substitute_trivial_operations();
                    }
                }
            }
            for jmp in block.jmps_mut() {
                match &mut jmp.term {
                    Jmp::Branch(_) | Jmp::Call { .. } | Jmp::CallOther { .. } => (),
                    Jmp::BranchInd(expr)
                    | Jmp::CBranch {
                        condition: expr, ..
                    }
                    | Jmp::CallInd { target: expr, .. }
                    | Jmp::Return(expr) => expr.substitute_trivial_operations(),
                }
            }
        }

        Vec::new()
    }

    fn assert_postconditions(
        _construction_input: &Self::ConstructionInput,
        _program: &Self::Input,
    ) {
    }
}
