use itertools::Itertools;

use crate::{
    abstract_domain::{AbstractLocation, DataDomain, IntervalDomain},
    intermediate_representation::{Def, Expression, Program},
};

use super::{
    global_block::GlobalMemorySeperation, global_block_analysis::vsa_result::SmallVsaResult,
};

pub fn build_stack_memory_blocks(
    program: &Program,
    value_sets: &impl SmallVsaResult<ValueDomain = DataDomain<IntervalDomain>>,
) -> GlobalMemorySeperation {
    let mut intervals = vec![];
    for sub in &program.subs {
        let first_block = sub.1.blocks().collect_vec()[0];
        let stack_register = first_block
            .defs()
            .find_map(|def| {
                if let Def::Assign {
                    var,
                    value: Expression::Phi { .. },
                } = &def.term
                {
                    if var.name.contains("RSP") {
                        Some(var)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .unwrap();
        let mut intervals = vec![];
        for block in &sub.1.term.blocks {
            for def in block.defs() {
                if let Some(address) = value_sets.eval_address_at_def(&def.tid) {
                    if let Some((abstract_location, interval)) = address.get_if_unique_target() {
                        match abstract_location.get_location() {
                            AbstractLocation::Register(stack_register) => {
                                intervals.push((def.tid.clone(), interval.clone()));
                            }
                            _ => (),
                        }
                    }
                }
            }
        }
    }

    GlobalMemorySeperation::new(intervals)
}
