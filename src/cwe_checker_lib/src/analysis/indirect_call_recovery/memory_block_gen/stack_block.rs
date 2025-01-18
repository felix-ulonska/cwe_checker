use std::collections::HashMap;

use crate::{analysis::{forward_interprocedural_fixpoint, graph::{intraprocedural_cfg::IntraproceduralCfg, Graph}}, intermediate_representation::{Program, Sub as Function}, prelude::Term};

/// Analysis for one Sub.
pub struct StackAnalysis<'a> {
    program: &'a Program,
    function: &'a Term<Function>,
    cfg: &'a Graph<'a>,
}

impl<'a> StackAnalysis {
    fn foo(&self) {}
    fn new(program: &'a Program, function: &'a Function) -> StackAnalysis<'a> {
        return StackAnalysis {
            program,
            function,
            cfg: IntraproceduralCfg::new(program, function).graph(),
        }
    }

    pub fn analyze_block(&self, sub: &Term<Function>) {
        // Do stack val analysis
        
    }

    fn get_cfg(&self) {
        return self.cfg;
    }
}

impl<'a, T: StackAnalysis<'a>> forward_interprocedural_fixpoint::Context<'a> for T {
    type Value = State;

    fn get_graph(&self) -> &Graph<'a> {
        self.get_cfg()
    }

    fn merge(&self, value1: &Self::Value, value2: &Self::Value) -> Self::Value {
        todo!()
    }

    fn update_def(&self, value: &Self::Value, def: &Term<crate::intermediate_representation::Def>) -> Option<Self::Value> {
        todo!()
    }

    fn update_jump(
        &self,
        value: &Self::Value,
        jump: &Term<crate::intermediate_representation::Jmp>,
        untaken_conditional: Option<&Term<crate::intermediate_representation::Jmp>>,
        target: &Term<crate::intermediate_representation::Blk>,
    ) -> Option<Self::Value> {
        todo!()
    }

    fn update_call(
        &self,
        value: &Self::Value,
        call: &Term<crate::intermediate_representation::Jmp>,
        target: &crate::analysis::graph::Node,
        calling_convention: &Option<String>,
    ) -> Option<Self::Value> {
        todo!()
    }

    fn update_return(
        &self,
        value: Option<&Self::Value>,
        value_before_call: Option<&Self::Value>,
        call_term: &Term<crate::intermediate_representation::Jmp>,
        return_term: &Term<crate::intermediate_representation::Jmp>,
        calling_convention: &Option<String>,
    ) -> Option<Self::Value> {
        todo!()
    }

    fn update_call_stub(&self, value: &Self::Value, call: &Term<crate::intermediate_representation::Jmp>) -> Option<Self::Value> {
        todo!()
    }

    fn specialize_conditional(
        &self,
        value: &Self::Value,
        condition: &crate::intermediate_representation::Expression,
        block_before_condition: &Term<crate::intermediate_representation::Blk>,
        is_true: bool,
    ) -> Option<Self::Value> {
        todo!()
    }
}

struct State {
    // TODO specific for architecture?
    register_state: HashMap::<String, u64>,
}

impl State {
    fn merge(&self, other: &State) {
    }
}

pub fn build_stack_block(program: &Program) {
    let stack_analysis = StackAnalysis::new();
    for sub in &program.subs {
        stack_analysis.analyze_block(sub.1);
    }
}
