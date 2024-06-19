use crate::intermediate_representation::{Jmp, Program, Sub as Function, Term, Tid};
use std::collections::HashSet;

use super::prelude::*;

/// Removes empty functions.
///
/// - Adds an artificial sink function.
/// - Rewrites calls to empty functions to artificial sink function and replaces
///   return target with artificial return block (as the artificial sink
///   function is noreturn).
/// - Removes empty functions.
///
/// # Guarantees
///
/// - Maintains: Existence of all CFT targets.
///
/// # Postconditions
///
/// 1. The program has no empty functions.
/// 2. The program has exactly one artificial sink function.
///
/// Run after:
/// - Adding an artificial return target block to each function.
///   [NoreturnExtFunctionsPass](super::NoreturnExtFunctionsPass)
pub struct RemoveEmptyFunctionsPass {
    empty_fn_tids: HashSet<Tid>,
}

impl IrPass for RemoveEmptyFunctionsPass {
    const NAME: &'static str = "RemoveEmptyFunctionsPass";
    const DBG_IR_FORM: debug::IrForm = debug::IrForm::EmptyFnRemoved;

    type Input = Program;
    type ConstructionInput = Self::Input;

    fn new(program: &Self::ConstructionInput) -> Self {
        Self {
            empty_fn_tids: program
                .functions()
                .filter_map(|f| {
                    if f.blocks.is_empty() {
                        Some(f.tid.clone())
                    } else {
                        None
                    }
                })
                .collect(),
        }
    }

    fn run(&mut self, program: &mut Self::Input) -> Vec<LogMessage> {
        let mut logs = Vec::new();

        // Remove empty functions.
        program
            .subs
            .retain(|fn_tid, _| !self.empty_fn_tids.contains(fn_tid));

        // Insert an artificial sink function.
        program.subs.insert(
            Tid::artificial_sink_fn(),
            Term::<Function>::artificial_sink(),
        );

        // Retarget calls to empty functions to artificial sink and
        // rewrite their returns to the artificial return target block for the
        // surrounding function.
        for (fn_tid, j) in program.jmps_mut_with_fn_tid() {
            match &mut j.term {
                Jmp::Call { target, return_ } if self.empty_fn_tids.contains(target) => {
                    logs.push(LogMessage::new_info(format!(
                        "{}: Rewrite call to empty function '{}' at {}.",
                        Self::NAME,
                        target,
                        j.tid
                    )));

                    *target = Tid::artificial_sink_fn();
                    *return_ = Some(Tid::artificial_return_target_for_fn(fn_tid));
                }
                _ => (),
            }
        }

        logs
    }

    fn assert_postconditions(_construction_input: &Self::ConstructionInput, program: &Self::Input) {
        // 1. The program has no empty functions.
        assert!(program.functions().all(|f| !f.blocks.is_empty()));
        // 2. The program has exactly one artificial sink function.
        assert!(
            program
                .functions()
                .filter(|f| f.tid.is_artificial_sink_fn())
                .count()
                == 1
        );
    }
}
