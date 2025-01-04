use std::collections::HashSet;

use crate::{intermediate_representation::{Def, Project}, utils::debug::IrForm};

use super::{prelude::{LogMessage, Program}, IrPass};

/// Computes register-SSA with a really crude approach 
/// For each register, we add a phi instruction at the start of each block. This is the opposite of
/// memory efficency.
pub struct SingleStaticAssigment;

impl IrPass for SingleStaticAssigment {

    const NAME: &'static str = "SingleStaticAssigment";

    const DBG_IR_FORM: super::prelude::debug::IrForm = IrForm::SingleStaticAssigment;

    type Input = Program;
    type ConstructionInput = Project;

    fn new(_construction_input: &Self::ConstructionInput) -> Self {
        todo!()
    }

    fn run(&mut self, program: &mut Self::Input) -> Vec<super::prelude::LogMessage> {
        let mut logs: Vec<LogMessage> = vec![];
        // We need to aggregate all names, as we do the really crude method!
        let mut var_names = HashSet::new();
        for sub in &program.subs {
            for blks in sub.1.blocks() {
                for defs in blks.defs() {
                    match &defs.term {
                        Def::Load { var, .. } | Def::Assign { var, .. } => var_names.insert(var.name.clone()),
                        Def::Store { .. } => false,
                    };
                }
            }
        }
        logs.push(
            LogMessage::new_info(
                format!("Found following var names {}", itertools::join(&var_names, ","))
            )
        );

        logs
    }

    fn assert_postconditions(construction_input: &Self::ConstructionInput, program: &Self::Input) {
        todo!()
    }
}

