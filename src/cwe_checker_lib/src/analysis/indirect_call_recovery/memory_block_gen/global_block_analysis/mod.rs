use std::collections::BTreeSet;

use ascent::rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use context::{AnalysisContext, State};

use crate::{
    analysis::forward_intraprocdural_fixpoint::create_computation,
    intermediate_representation::{ir_passes::SPLIT_SYMBOL, Def, Expression, Program, Variable},
    prelude::{ByteSize, Term},
};

mod context;
mod value_specialization;

pub fn foo(program: &Program) {
    program.subs.iter().for_each(|sub| {
        println!("Iteration {}", sub.1.name);
        if sub.1.name != "main" {
            return
        }
        let analysis = AnalysisContext::new(program, sub.1);
        let first_block = sub.1.blocks().next().unwrap();
        let stack_var = match &first_block.term.defs().find(|def| {
            if let Def::Assign {
                var,
                value: Expression::Phi(_),
            } = &def.term
            {
                var.name.split(SPLIT_SYMBOL).next().unwrap() == "RSP"
            } else {
                false
            }
        }) {
            Some(Term { term: Def::Assign { var, value: _value }, ..}) => var.clone(),
            _ => Variable {name: "RSP".to_string(), size: ByteSize::new(8), is_temp: false} 
        };

        let mut compution = create_computation(
            analysis,
            Some(State::new(
                &stack_var,
                sub.0.clone(),
                BTreeSet::new().into(),
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
    })
    //.collect::<Vec<()>>();
}
