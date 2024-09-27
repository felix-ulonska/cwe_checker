use super::prelude::*;

/// TODO
pub struct IntraproceduralDeadBlockElimPass;

impl IrPass for IntraproceduralDeadBlockElimPass {
    const NAME: &'static str = "IntraproceduralDeadBlockElimPass";
    const DBG_IR_FORM: debug::IrForm = debug::IrForm::IntraproceduralDeadBlocksElimed;

    type Input = Program;
    type ConstructionInput = ();

    fn new(_construction_input: &Self::ConstructionInput) -> Self {
        Self
    }

    fn run(&mut self, _program: &mut Self::Input) -> Vec<LogMessage> {
        Vec::new()
    }

    fn assert_postconditions(
        _construction_input: &Self::ConstructionInput,
        _program: &Self::Input,
    ) {
    }
}
