use ascent::hashbrown::HashMap;
use itertools::Itertools;

use crate::{
    analysis::pointer_inference::Config,
    intermediate_representation::{
        ir_passes::SPLIT_SYMBOL, Def, Expression, Jmp, Program, Variable,
    },
    prelude::Term,
};

#[derive(Clone, Eq, Hash, PartialEq, Default, Debug)]
pub struct HeapBlock {
    /// TID is the calling instruction
    pub id: String,
}

#[derive(Clone, Eq, PartialEq, Default, Debug)]
pub struct HeapAnalysis {
    /// SSA register mapped to heapID
    pub register_with_heap: HashMap<Variable, HeapBlock>,
}

/// We changed the algorithm for global memory. We use the PI and then build a set where no
/// overlapping address ranges.
pub fn build_heap_blocks(program: &Program, config: &Config) -> HeapAnalysis {
    let mut register_with_heap = HashMap::<Variable, HeapBlock>::new();
    for block in program.blocks() {
        for jmp in block.jmps() {
            let Jmp::Call { target, return_ } = &jmp.term else {
                continue;
            };
            let Some(extern_smbol) = program.extern_symbols.get(target) else {
                continue;
            };
            let is_malloc_like = config.allocation_symbols.contains(&extern_smbol.name);
            if !is_malloc_like {
                continue;
            }
            let Some(blk_return) = return_ else { continue };
            let block = program
                .blocks()
                .into_iter()
                .find(|block| block.tid == *blk_return)
                .unwrap();
            for def in block.defs() {
                let Term {
                    term:
                        Def::Assign {
                            var,
                            value: Expression::Phi(_),
                        },
                    ..
                } = def
                else {
                    continue;
                };
                // check that it is the rax phi instruction
                let Some(("RAX", _)) = var.name.split(SPLIT_SYMBOL).collect_tuple() else {
                    continue;
                };

                register_with_heap.insert(
                    var.clone(),
                    HeapBlock {
                        id: jmp.tid.to_string() + "_heap",
                    },
                );
            }
        }
    }

    HeapAnalysis { register_with_heap }
}
