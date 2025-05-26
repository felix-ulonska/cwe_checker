use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
};

use crate::{intermediate_representation::Project, prelude::Tid};

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct Function {
    pub tid: Tid,
    pub first_instruction: u64,
    pub first_block_tid: Tid,
    pub name: String,
    pub is_at_function: bool,
}

impl Display for Function {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AtFunction: {}", self.name)
    }
}

/// Get all adress taken functions.
pub fn get_at_functions(project: &Project) -> HashSet<Function> {
    let program = &project.program;
    let code_refs = &project.code_references;

    let mut adress_taken_function = HashSet::new();

    let mut used_first_addresses = HashSet::new();

    for code_ref in code_refs {
        used_first_addresses.insert(code_ref.to as u64);
    }

    for function in program.functions() {
        let Some(first_block) = function.blocks().next() else {
            continue;
        };

        adress_taken_function.insert(Function {
            tid: function.tid.clone(),
            first_instruction: function.code_range().0,
            first_block_tid: first_block.tid.clone(),
            name: function.name.clone(),
            // TODO: add actually check that this is an AT Function?
            is_at_function: false,
        });
    }

    adress_taken_function
}

pub fn get_at_functions_by_key(project: &Project) -> HashMap<u64, Function> {
    let mut by_key = HashMap::new();
    for at_function in get_at_functions(project) {
        by_key.insert(at_function.first_instruction, at_function);
    }

    by_key
}
