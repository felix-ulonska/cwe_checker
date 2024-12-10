use super::prelude::*;

/// Removes listed entry points that are not defined within the program or are
/// empty.
///
/// # Guarantees
///
/// Should not interfere with any other pass.
///
/// # Postconditions
///
/// 1. All listed entry points are defined, nonempty functions within the
///    program.
///
/// # Run After
///
/// - Empty functions have been removed. [Removing them afterwards might violate
///   Postcondition 1]. (Not necessary but lets be conservative.)
/// - Stubs for external functions have been removed. [Removing them afterwards
///   might violate Postcondition 1].
pub struct EntryPointsPass;

impl IrPass for EntryPointsPass {
    const NAME: &'static str = "EntryPointsPass";
    const DBG_IR_FORM: debug::IrForm = debug::IrForm::EntryPointsExist;

    type Input = Program;
    type ConstructionInput = ();

    fn new(_construction_input: &Self::ConstructionInput) -> Self {
        Self
    }

    fn run(&mut self, program: &mut Self::Input) -> Vec<LogMessage> {
        let mut logs = Vec::new();

        // Keep only entry points that are defined and nonempty.
        program.entry_points.retain(|ep_tid| {
            let defined_and_nonempty = program
                .subs
                .get(ep_tid)
                .is_some_and(|ep_fn| !ep_fn.blocks.is_empty());

            if !defined_and_nonempty {
                logs.push(LogMessage::new_info(format!(
                    "{}: Entry point {} undefined or empty.",
                    Self::NAME,
                    ep_tid
                )))
            }

            defined_and_nonempty
        });

        logs
    }

    fn assert_postconditions(_construction_input: &Self::ConstructionInput, program: &Self::Input) {
        for ep_tid in program.entry_points.iter() {
            let ep_fn = program.subs.get(ep_tid);

            assert!(ep_fn.is_some(), "Entry point {} is undefined.", ep_tid);
            assert!(
                !ep_fn.unwrap().blocks.is_empty(),
                "Entry point {} is empty.",
                ep_tid
            );
        }
    }
}
