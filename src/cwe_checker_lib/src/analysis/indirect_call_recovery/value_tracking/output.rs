use std::{collections::HashMap, sync::Arc};

use ascent::rayon::iter::{IntoParallelRefMutIterator, ParallelIterator};
use itertools::Itertools;

use crate::{
    analysis::indirect_call_recovery::function_taken::Function,
    intermediate_representation::Program,
};

use super::{AscentProgram, Blk};

#[derive(Clone)]
pub struct IndirectCalls {
    indirect_calls: HashMap<Blk, Vec<Arc<Function>>>,
}

impl IndirectCalls {
    pub fn from_ascent_prog(prog: &AscentProgram) -> Self {
        let mut results: HashMap<Blk, Vec<Arc<Function>>> = HashMap::new();
        for (blk, func) in &prog.func_call_targets {
            results.entry(blk.clone()).or_default().push(func.clone());
        }

        IndirectCalls {
            indirect_calls: results,
        }
    }

    pub fn add_to_program(&self, program: &mut Program) {
        program
            .blocks_mut()
            .collect_vec()
            .par_iter_mut()
            .for_each(|blk| {
                let Some(targets) = self.indirect_calls.get(&Blk(blk.tid.clone().into())) else {
                    blk.set_ind_call_targets(vec![]);
                    return;
                };
                blk.set_ind_call_targets(targets.iter().map(|func| func.tid.clone()));
            });
    }
}
