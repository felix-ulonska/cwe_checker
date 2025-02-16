use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
};

use crate::{intermediate_representation::Project, prelude::Tid};

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct AtFunction {
    pub tid: Tid,
    pub first_instruction: u64,
    pub first_block_tid: Tid,
}

impl Display for AtFunction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AtFunction: {}", self.tid)
    }
}

/// Get all adress taken functions.
pub fn get_at_functions(project: &Project) -> HashSet<AtFunction> {
    let program = &project.program;
    let code_refs = &project.code_references;

    let mut first_instruction_to_func = HashMap::new();
    let mut func_to_first_block = HashMap::new();

    for function in program.functions() {
        first_instruction_to_func.insert(function.code_range().0, function.tid.clone());
        let Some(first_block) = function.blocks().next() else {
            continue;
        };
        func_to_first_block.insert(function.tid.clone(), first_block.tid.clone());
    }

    let mut adress_taken_function = HashSet::new();

    for code_ref in code_refs {
        let Some(function_tid) = first_instruction_to_func.get(&(code_ref.to as u64)) else {
            continue;
        };
        let Some(block_tid) = func_to_first_block.get(&(function_tid)) else {
            continue;
        };
        adress_taken_function.insert(AtFunction {
            tid: function_tid.clone(),
            first_instruction: code_ref.to as u64,
            first_block_tid: block_tid.clone(),
        });
    }

    adress_taken_function
}
