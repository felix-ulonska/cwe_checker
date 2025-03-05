use std::collections::{BTreeSet, HashMap};

use ascent::rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use context::{fill_vsa_result_maps, AnalysisContext, State};
use vsa_result::{GlobalBlockAnalysisResult, RegisterState};

use crate::{
    analysis::{fixpoint::Computation, forward_intraprocdural_fixpoint::{create_computation, GeneralizedContext}, graph::Node},
    intermediate_representation::{ir_passes::SPLIT_SYMBOL, Def, Expression, Program, RuntimeMemoryImage, Variable},
    prelude::{ByteSize, Term}, utils::binary::MemorySegment,
};

mod context;
mod value_specialization;
pub mod vsa_result;

pub fn foo(program: &Program, memory_segments: &RuntimeMemoryImage) -> GlobalBlockAnalysisResult {
    println!("MemorySegments: {:#?}", memory_segments);
    program.subs.iter().map(|sub| {
        println!("Iteration {}", sub.1.name);
        let analysis = AnalysisContext::new(program, sub.1);
        //let first_block = sub.1.blocks().next().unwrap();
        //let stack_var = match &first_block.term.defs().find(|def| {
        //    if let Def::Assign {
        //        var,
        //        value: Expression::Phi(_),
        //    } = &def.term
        //    {
        //        var.name.split(SPLIT_SYMBOL).next().unwrap() == "RSP"
        //    } else {
        //        false
        //    }
        //}) {
        //    Some(Term { term: Def::Assign { var, value: _value }, ..}) => var.clone(),
        //    _ => Variable {name: "RSP".to_string(), size: ByteSize::new(8), is_temp: false} 
        //};

        let mut compution = create_computation(
            analysis,
            Some(State::new(
                //&stack_var,
                sub.0.clone(),
                memory_segments
            )),
        );
        compution.compute();
        for blk in sub.1.blocks() {
            for def in blk.defs.iter() {
                println!("\t {}", def);
            }
        }
        compution
            .node_values()
            .iter()
            .for_each(|(node_index, node_value)| {
                println!("Got {}: {}", node_index.index(), node_value)
            });
        println!("Done Iteration {}", sub.1.name);

        fill_vsa_result_maps(compution)
    }).fold(GlobalBlockAnalysisResult::new_empty(), |acc, item| {
        acc.merge(&item)
    })
    //.collect::<Vec<()>>();
}
