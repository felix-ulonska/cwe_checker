use super::prelude::*;
use crate::intermediate_representation::{Jmp as IrJmp, Tid};

use std::collections::hash_map::Entry;
use std::collections::HashMap;

/// Call into external functions directly.
///
/// - Removes stubs for external functions.
/// - Replaces calls to stubs for external function with call to external
///   function.
///
/// # Guarantees
///
/// - Preserves: All CFT targets exist.
///
/// # Postconditions
///
/// # Run After
pub struct ReplaceCallsToExtFnsPass {
    stub_tid_to_ext_fn_tid_map: HashMap<Tid, Tid>,
}

impl IrPass for ReplaceCallsToExtFnsPass {
    const NAME: &'static str = "ReplaceCallsToExtFnsPass";
    const DBG_IR_FORM: debug::IrForm = debug::IrForm::ExtCallsReplaced;

    type Input = Program;
    type ConstructionInput = Self::Input;

    fn new(program: &Self::ConstructionInput) -> Self {
        let mut stub_tid_to_ext_fn_tid_map = HashMap::new();

        for ext_fn in program.extern_symbols.values() {
            for stub_tid in ext_fn.addresses.iter().map(Tid::new_function) {
                match stub_tid_to_ext_fn_tid_map.entry(stub_tid) {
                    Entry::Vacant(e) => e.insert(ext_fn.tid.clone()),
                    Entry::Occupied(_) => {
                        panic!("Mapping of stubs to external functions is not unique.")
                    }
                };
            }
        }

        Self {
            stub_tid_to_ext_fn_tid_map,
        }
    }

    fn run(&mut self, program: &mut Self::Input) -> Vec<LogMessage> {
        let mut logs = Vec::new();

        // Rewrite potential targets of indirect calls.

        // Rewrite calls to external function's stubs.
        for j in program.jmps_mut() {
            let IrJmp::Call { target, .. } = &mut j.term else {
                continue;
            };
            let Some(ext_fn_tid) = self.stub_tid_to_ext_fn_tid_map.get(target) else {
                continue;
            };

            logs.push(LogMessage::new_info(format!(
                "{}: Replaced call {} @ {} with call to {}.",
                Self::NAME,
                target,
                j.tid,
                ext_fn_tid
            )));

            *target = ext_fn_tid.clone();
        }

        // Remove stubs from the program.
        for stub_tid in self.stub_tid_to_ext_fn_tid_map.keys() {
            program.subs.remove(stub_tid).unwrap();

            logs.push(LogMessage::new_info(format!(
                "{}: Removed stub {}.",
                Self::NAME,
                stub_tid
            )));
        }

        logs
    }

    fn assert_postconditions(
        _construction_input: &Self::ConstructionInput,
        _program: &Self::Input,
    ) {
    }
}
