use std::collections::{HashMap, HashSet};

use crate::{intermediate_representation::Project, prelude::Tid};

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct AtFunction {
    pub tid: Tid,
    pub first_instruction: u64,
}

/// Get all adress taken functions.
pub fn get_at_functions(project: &Project) -> HashSet<AtFunction> {
    let program = &project.program;
    let code_refs = &project.code_references;

    let mut first_instruction_to_func = HashMap::new();

    for function in program.functions() {
        first_instruction_to_func.insert(function.code_range().0, function.tid.clone());
    }

    let mut adress_taken_function = HashSet::new();

    for code_ref in code_refs {
        if let Some(function_tid) = first_instruction_to_func.get(&(code_ref.to as u64)) {
            adress_taken_function.insert(AtFunction {
                tid: function_tid.clone(),
                first_instruction: code_ref.to as u64,
            });
        }
    }

    adress_taken_function
}
