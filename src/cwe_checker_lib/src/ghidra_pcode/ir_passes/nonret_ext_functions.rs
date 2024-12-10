use super::prelude::*;
use crate::intermediate_representation::{Jmp as IrJmp, Tid};

use std::collections::HashSet;

/// Rewrites return targets of calls to from noreturn functions.
///
/// - Inserts an artificial return target block into every nonempty function.
/// - Rewrites return locations of calls to noreturn ext functions to artificial
///   return target block.
///
/// # Guarantees
///
/// - Preserves existence of CFT targets.
///
/// # Postconditions
///
/// 1. Every nonempty function has zero or one artificial return target blocks.
///    [All incoming edges are from returns of calls to noreturn functions.]
///
/// # Run After
///
/// - Rewriting calls to external functions to skip stubs. [Calls to external
///   functions are assumed to be direct.]
///   [ReplaceCallsToExtFnsPass](super::ReplaceCallsToExtFnsPass)
/// - Inlining. [Might violate 1st Postcondition.]
///   [InliningPass](super::InliningPass)
pub struct NoreturnExtFunctionsPass {
    /// TIDS of non returning external functions.
    nonret_ext_fn_tids: HashSet<Tid>,
}

impl IrPass for NoreturnExtFunctionsPass {
    const NAME: &'static str = "NoreturnExtFunctionsPass";
    const DBG_IR_FORM: debug::IrForm = debug::IrForm::NonRetExtFunctionsMarked;

    type Input = Program;
    type ConstructionInput = Self::Input;

    fn new(program: &Self::ConstructionInput) -> Self {
        Self {
            nonret_ext_fn_tids: program
                .extern_symbols
                .values()
                .filter_map(|ext_fn| {
                    if ext_fn.no_return {
                        Some(ext_fn.tid.clone())
                    } else {
                        None
                    }
                })
                .collect(),
        }
    }

    fn run(&mut self, program: &mut Self::Input) -> Vec<LogMessage> {
        let mut logs = Vec::new();

        // Add artificial return target blocks to all nonempty functions.
        for f in program.functions_mut().filter(|f| !f.blocks.is_empty()) {
            f.add_artifical_return_target();
        }

        for (fn_tid, j_tid, return_target) in
            program
                .jmps_mut_with_fn_tid()
                .filter_map(|(fn_tid, j)| match &mut j.term {
                    IrJmp::Call {
                        target,
                        return_: return_target,
                    } if self.nonret_ext_fn_tids.contains(target) => {
                        Some((fn_tid, &j.tid, return_target))
                    }
                    _ => None,
                })
        {
            logs.push(LogMessage::new_info(format!(
                "{}: Change return target of nonret call @ {} from {:?} with artificial return target.",
                Self::NAME, j_tid, return_target
            )));

            // Rewrite return of call to nonret ext function.
            *return_target = Some(Tid::artificial_return_target_for_fn(fn_tid));
        }

        logs
    }

    fn assert_postconditions(_construction_input: &Self::ConstructionInput, program: &Self::Input) {
        // 1. Every nonempty function has zero or one artificial return target
        //    blocks.
        //    [All incoming edges are from returns of calls to noreturn
        //    functions.]
        for f in program.functions() {
            let num_artificial_return_target = f
                .blocks()
                .filter(|b| b.tid.is_artificial_return_target_block())
                .count();

            assert!(num_artificial_return_target == 0 || num_artificial_return_target == 1);
        }
    }
}
