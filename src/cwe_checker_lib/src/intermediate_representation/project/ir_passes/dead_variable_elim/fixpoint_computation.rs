use crate::analysis::backward_interprocedural_fixpoint::{self, create_computation};
use crate::analysis::graph::{self, Graph, Node};
use crate::analysis::interprocedural_fixpoint_generic::NodeValue;
use crate::intermediate_representation::*;
use std::collections::{BTreeSet, HashMap};

/// Given the variables that are alive after execution of the given `Def` term,
/// modify the set of variables to the ones that are alive before the execution
/// of the `Def` term.
pub fn update_alive_vars_by_def(alive_variables: &mut BTreeSet<Variable>, def: &Term<Def>) {
    match &def.term {
        Def::Assign { var, value } => {
            if alive_variables.contains(var) {
                alive_variables.remove(var);
                for input_var in value.input_vars() {
                    alive_variables.insert(input_var.clone());
                }
            } // The else-case is a dead store whose inputs do not change the set of alive variables.
        }
        Def::Load { var, address } => {
            alive_variables.remove(var);
            for input_var in address.input_vars() {
                alive_variables.insert(input_var.clone());
            }
        }
        Def::Store { address, value } => {
            for input_var in address.input_vars() {
                alive_variables.insert(input_var.clone());
            }
            for input_var in value.input_vars() {
                alive_variables.insert(input_var.clone());
            }
        }
    }
}

/// The context struct for the alive variables fixpoint computation.
///
/// The computation is a intraprocedural backwards fixpoint calculation
/// that stores at each node the set of all registers that are assumed to be alive.
/// A register is alive if its content is (assumed to be) read before it is overwritten by another value assignment.
struct Context<'a> {
    /// The reversed control flow graph of the program.
    graph: &'a Graph<'a>,
    /// The set of all physical base registers (i.e. no sub registers).
    /// This is the set of registers that are assumed to be alive at call/return instructions
    /// and all other places in the control flow graph,
    /// where the next instruction to be executed may not be known.
    all_phys_registers: &'a BTreeSet<Variable>,
}

impl<'a> Context<'a> {
    /// Create a new context object for the given project and reversed control flow graph.
    pub fn new(all_phys_registers: &'a BTreeSet<Variable>, graph: &'a Graph) -> Context<'a> {
        Context {
            graph,
            all_phys_registers,
        }
    }
}

impl<'a> backward_interprocedural_fixpoint::Context<'a> for Context<'a> {
    /// The value at each node is the set of variables that are known to be alive.
    type Value = BTreeSet<Variable>;

    /// Get the reversed control flow graph on which the fixpoint computation operates.
    fn get_graph(&self) -> &Graph<'a> {
        self.graph
    }

    /// Merge by taking the union of the two sets of alive registers.
    fn merge(&self, var_set_1: &Self::Value, var_set_2: &Self::Value) -> Self::Value {
        var_set_1.union(var_set_2).cloned().collect()
    }

    /// Update the set of alive registers according to the effect of the given `Def` term.
    fn update_def(&self, alive_variables: &Self::Value, def: &Term<Def>) -> Option<Self::Value> {
        let mut alive_variables = alive_variables.clone();
        update_alive_vars_by_def(&mut alive_variables, def);
        Some(alive_variables)
    }

    /// Update the set of alive registers according to the effect of the given jump term.
    /// Adds input variables of jump conditions or jump target computations to the set of alive variables.
    fn update_jumpsite(
        &self,
        alive_vars_after_jump: &Self::Value,
        jump: &Term<Jmp>,
        untaken_conditional: Option<&Term<Jmp>>,
        _jumpsite: &Term<Blk>,
    ) -> Option<Self::Value> {
        let mut alive_variables = alive_vars_after_jump.clone();
        match &jump.term {
            Jmp::CBranch {
                condition: expression,
                ..
            }
            | Jmp::BranchInd(expression) => {
                for input_var in expression.input_vars() {
                    alive_variables.insert(input_var.clone());
                }
            }
            _ => (),
        }
        if let Some(Term {
            tid: _,
            term: Jmp::CBranch { condition, .. },
        }) = untaken_conditional
        {
            for input_var in condition.input_vars() {
                alive_variables.insert(input_var.clone());
            }
        }
        Some(alive_variables)
    }

    /// At a call instruction we assume all physical registers to be alive.
    /// Also adds inputs for the call target computation to the set of alive registers.
    fn update_callsite(
        &self,
        _target_value: Option<&Self::Value>,
        _return_value: Option<&Self::Value>,
        _caller_sub: &Term<Sub>,
        call: &Term<Jmp>,
        _return_: &Term<Jmp>,
    ) -> Option<Self::Value> {
        let mut alive_variables = self.all_phys_registers.clone();
        if let Jmp::CallInd { target, .. } = &call.term {
            for input_var in target.input_vars() {
                alive_variables.insert(input_var.clone());
            }
        }
        Some(alive_variables)
    }

    /// Interprocedural edge that is ignored by the fixpoint computation.
    fn split_call_stub(&self, _combined_value: &Self::Value) -> Option<Self::Value> {
        None
    }

    /// At a return instruction we assume all physical registers to be alive.
    fn split_return_stub(
        &self,
        _combined_value: &Self::Value,
        _returned_from_sub: &Term<Sub>,
    ) -> Option<Self::Value> {
        Some(self.all_phys_registers.clone())
    }

    /// At a call instruction we assume all physical registers to be alive.
    /// Also adds inputs for the call target computation to the set of alive registers.
    fn update_call_stub(
        &self,
        _value_after_call: &Self::Value,
        call: &Term<Jmp>,
    ) -> Option<Self::Value> {
        let mut alive_variables = self.all_phys_registers.clone();
        if let Jmp::CallInd { target, .. } = &call.term {
            for input_var in target.input_vars() {
                alive_variables.insert(input_var.clone());
            }
        }
        Some(alive_variables)
    }

    /// This function just clones its input as it is not used by the fixpoint computation.
    fn specialize_conditional(
        &self,
        alive_vars_after_jump: &Self::Value,
        _condition: &Expression,
        _is_true: bool,
    ) -> Option<Self::Value> {
        Some(alive_vars_after_jump.clone())
    }
}

/// Compute alive variables by means of an intraprocedural fixpoint computation.
///
/// Returns a map that assigns to each basic block `Tid` the set of all
/// variables that are alive at the end of the basic block.
pub fn compute_alive_vars(
    all_phys_registers: &BTreeSet<Variable>,
    program: &Program,
) -> HashMap<Tid, BTreeSet<Variable>> {
    let mut graph = graph::get_program_cfg(program);
    graph.reverse();

    let context = Context::new(all_phys_registers, &graph);

    let mut computation = create_computation(context, None);
    for node in graph.node_indices() {
        match graph[node] {
            Node::BlkStart(_, _) => (),
            Node::BlkEnd(blk, _sub) => {
                if graph
                    .neighbors_directed(node, petgraph::Incoming)
                    .next()
                    .is_none()
                {
                    // A dead end in the CFG has no incoming edges in the reversed CFG.
                    // Since dead ends are mostly due to cases where the control flow graph is incomplete,
                    // we assume that all registers are alive at the end of the block.
                    let mut alive_vars = all_phys_registers.clone();
                    for jmp in blk.term.jmps.iter() {
                        match &jmp.term {
                            Jmp::CallInd {
                                target: expression, ..
                            }
                            | Jmp::BranchInd(expression)
                            | Jmp::CBranch {
                                condition: expression,
                                ..
                            } => {
                                // The expressions may contain virtual registers
                                for input_var in expression.input_vars() {
                                    alive_vars.insert(input_var.clone());
                                }
                            }
                            _ => (),
                        }
                    }
                    computation.set_node_value(node, NodeValue::Value(alive_vars));
                } else {
                    computation.set_node_value(node, NodeValue::Value(BTreeSet::new()))
                }
            }
            Node::CallReturn { .. } => {
                computation.set_node_value(node, NodeValue::Value(BTreeSet::new()));
            }
            Node::CallSource { .. } => {
                computation.set_node_value(
                    node,
                    NodeValue::CallFlowCombinator {
                        call_stub: Some(BTreeSet::new()),
                        interprocedural_flow: Some(BTreeSet::new()),
                    },
                );
            }
        }
    }
    computation.compute_with_max_steps(100);
    if !computation.has_stabilized() {
        panic!("Fixpoint for dead register assignment removal did not stabilize.");
    }

    let mut results = HashMap::new();
    for node in graph.node_indices() {
        if let Node::BlkEnd(blk, _sub) = graph[node] {
            if let Some(NodeValue::Value(alive_vars)) = computation.get_node_value(node) {
                results.insert(blk.tid.clone(), alive_vars.clone());
            } else {
                panic!("Error during dead variable elimination computation.")
            }
        }
    }

    results
}

/// For the given `block` look up the variables alive at the end of the block via the given `alive_vars_map`
/// and then remove those register assignment `Def` terms from the block
/// that represent dead assignments.
/// An assignment is considered dead if the register is not read before its value is overwritten by another assignment.
pub fn remove_dead_var_assignments_of_block(
    block: &mut Term<Blk>,
    alive_vars_map: &HashMap<Tid, BTreeSet<Variable>>,
) {
    let mut alive_vars = alive_vars_map.get(&block.tid).unwrap().clone();
    // Defs of the block in reverse order with dead assignments removed.
    let mut cleaned_defs = Vec::new();

    for def in block.term.defs.iter().rev() {
        match &def.term {
            Def::Assign { var, .. } if !alive_vars.contains(var) => (), // Dead Assignment
            _ => {
                cleaned_defs.push(def.clone());
                // Only do the update step if we actually keep the def.
                // Otherwise we would add the inputs variables of the rhs
                // expression to the alive variables even though the statement
                // "using" them is gone.
                update_alive_vars_by_def(&mut alive_vars, def);
            }
        }
    }

    block.term.defs = cleaned_defs.into_iter().rev().collect();
}
