use crate::abstract_domain::{AbstractDomain, CheapToClone};
use crate::analysis::backward_interprocedural_fixpoint::{self, create_computation};
use crate::analysis::graph::{Graph, Node};
use crate::analysis::interprocedural_fixpoint_generic::NodeValue;
use crate::intermediate_representation::*;

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

/// Given the variables that are alive after execution of the given `Def` term,
/// modify the set of variables to the ones that are alive before the execution
/// of the `Def` term.
fn update_alive_vars_by_def<'a>(
    all_variables: &BTreeSet<&'a Variable>,
    alive_variables: &mut AliveVariables<'a>,
    def: &Term<Def>,
) {
    match &def.term {
        Def::Assign { var, value } => {
            if alive_variables.contains(var) {
                alive_variables.remove(var);
                for input_var in value.input_vars() {
                    let var = all_variables.get(input_var);
                    match var {
                        Some(var) => alive_variables.insert(var),
                        None => panic!("Variable {} used at {} is not known.", input_var, def.tid),
                    }
                }
            } // The else-case is a dead store whose inputs do not change the set of alive variables.
        }
        Def::Load { var, address } => {
            alive_variables.remove(var);
            for input_var in address.input_vars() {
                let var = all_variables.get(input_var);
                match var {
                    Some(var) => alive_variables.insert(var),
                    None => panic!("Variable {} used at {} is not known.", input_var, def.tid),
                }
            }
        }
        Def::Store { address, value } => {
            for input_var in address.input_vars() {
                let var = all_variables.get(input_var);
                match var {
                    Some(var) => alive_variables.insert(var),
                    None => panic!("Variable {} used at {} is not known.", input_var, def.tid),
                }
            }
            for input_var in value.input_vars() {
                let var = all_variables.get(input_var);
                match var {
                    Some(var) => alive_variables.insert(var),
                    None => panic!("Variable {} used at {} is not known.", input_var, def.tid),
                }
            }
        }
    }
}

/// The context struct for the alive variables fixpoint computation.
///
/// The computation is a intraprocedural backwards fixpoint calculation
/// that stores at each node the set of all registers that are assumed to be alive.
/// A register is alive if its content is (assumed to be) read before it is overwritten by another value assignment.
struct Context<'a, 'b> {
    /// The reversed control flow graph of the program.
    graph: &'a Graph<'a>,
    /// The set of all physical base registers (i.e. no sub registers).
    ///
    /// This is the set of registers that are assumed to be alive at call/return
    /// instructions and all other places in the control flow graph, where the
    /// next instruction to be executed may not be known.
    all_phys_registers: AliveVariables<'b>,
    /// The set of all variables used by the program.
    all_variables: BTreeSet<&'b Variable>,
}

impl<'a, 'b> Context<'a, 'b> {
    /// Create a new context object for the given project and reversed control
    /// flow graph.
    pub fn new(
        all_variables: BTreeSet<&'b Variable>,
        all_phys_registers: AliveVariables<'b>,
        graph: &'a Graph,
    ) -> Context<'a, 'b> {
        Context {
            graph,
            all_phys_registers,
            all_variables,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Default)]
struct AliveVariables<'a> {
    inner: Arc<AliveVariablesInner<'a>>,
}

impl CheapToClone for AliveVariables<'_> {}

#[derive(Clone, PartialEq, Eq, Default)]
enum AliveVariablesInner<'a> {
    /// All variables are alive.
    // This variant is not handled properly so it should never be constructed.
    // In practice it should never occur that all variables are alive.
    #[allow(dead_code)]
    Top,
    /// A subset of all variables is alive.
    Vars(BTreeSet<&'a Variable>),
    /// No variables are alive.
    #[default]
    Bottom,
}

impl<'a> AliveVariables<'a> {
    fn new_vars(vars: BTreeSet<&'a Variable>) -> Self {
        Self {
            inner: Arc::new(if vars.is_empty() {
                AliveVariablesInner::Bottom
            } else {
                AliveVariablesInner::Vars(vars)
            }),
        }
    }

    fn to_owned(&self) -> BTreeSet<&'a Variable> {
        use AliveVariablesInner::*;
        match &*self.inner {
            Top => panic!(),
            Bottom => BTreeSet::new(),
            Vars(vars) => vars.clone(),
        }
    }

    /// Removes `var` from the set of alive variables.
    fn remove(&mut self, var: &Variable) {
        use AliveVariablesInner::*;
        match &*self.inner {
            Top => panic!(),
            Bottom => (),
            Vars(_) => {
                let vars = Arc::make_mut(&mut self.inner);

                if let Vars(vars) = vars {
                    vars.remove(var);

                    if vars.is_empty() {
                        self.inner = Arc::new(AliveVariablesInner::Bottom);
                    }
                }
            }
        }
    }

    /// Returns true iff `var` is alive.
    fn contains(&self, var: &Variable) -> bool {
        use AliveVariablesInner::*;
        match &*self.inner {
            Top => true,
            Bottom => false,
            Vars(vars) => (*vars).contains(var),
        }
    }

    /// Adds `var` to the set of alive variables.
    fn insert(&mut self, var: &'a Variable) {
        use AliveVariablesInner::*;
        match &*self.inner {
            Top => (),
            Bottom => {
                let mut vars = BTreeSet::new();
                vars.insert(var);

                self.inner = Arc::new(AliveVariablesInner::Vars(vars));
            }
            Vars(vars) if !vars.contains(var) => {
                let vars = Arc::make_mut(&mut self.inner);

                if let Vars(vars) = vars {
                    vars.insert(var);
                }
            }
            _ => (),
        }
    }
}

impl<'a> AbstractDomain for AliveVariables<'a> {
    fn merge(&self, other: &Self) -> Self {
        if self == other {
            return self.clone();
        }

        use AliveVariablesInner::*;
        match (&*self.inner, &*other.inner) {
            (Top, Top) | (Top, _) | (_, Bottom) => self.clone(),
            (_, Top) | (Bottom, _) => other.clone(),
            (Vars(a), Vars(b)) => {
                debug_assert!(!a.is_empty());
                debug_assert!(!b.is_empty());

                let union = a.union(b).cloned().collect::<BTreeSet<&'a Variable>>();
                // Note: Incorrect if the union should ever be all variables.
                //       But this should not happen in practice.

                AliveVariables {
                    inner: Arc::new(AliveVariablesInner::Vars(union)),
                }
            }
        }
    }

    fn is_top(&self) -> bool {
        matches!(*self.inner, AliveVariablesInner::Top)
    }
}

impl<'a, 'b> backward_interprocedural_fixpoint::Context<'a> for Context<'a, 'b> {
    /// The value at each node is the set of variables that are known to be alive.
    type Value = AliveVariables<'b>;

    /// Get the reversed control flow graph on which the fixpoint computation operates.
    fn get_graph(&self) -> &Graph<'a> {
        self.graph
    }

    /// Merge by taking the union of the two sets of alive registers.
    fn merge(&self, var_set_1: &Self::Value, var_set_2: &Self::Value) -> Self::Value {
        var_set_1.merge(var_set_2)
    }

    /// Update the set of alive registers according to the effect of the given
    /// `Def` term.
    fn update_def(&self, alive_variables: &Self::Value, def: &Term<Def>) -> Option<Self::Value> {
        let mut alive_variables = alive_variables.clone();

        update_alive_vars_by_def(&self.all_variables, &mut alive_variables, def);
        Some(alive_variables)
    }

    /// Update the set of alive registers according to the effect of the given
    /// jump term.
    ///
    /// Adds input variables of jump conditions or jump target computations to
    /// the set of alive variables.
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
                    alive_variables.insert(self.all_variables.get(input_var).unwrap());
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
                alive_variables.insert(self.all_variables.get(input_var).unwrap());
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
                alive_variables.insert(self.all_variables.get(input_var).unwrap());
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
                alive_variables.insert(self.all_variables.get(input_var).unwrap());
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
pub fn compute_alive_vars<'a, 'b>(
    all_variables: &'b BTreeSet<Variable>,
    all_phys_registers: &'b BTreeSet<Variable>,
    graph: &'a Graph,
) -> HashMap<Tid, BTreeSet<&'b Variable>> {
    let all_variables = all_variables.iter().collect::<BTreeSet<&'b Variable>>();
    let all_phys_registers = AliveVariables::new_vars(
        all_phys_registers
            .iter()
            .collect::<BTreeSet<&'b Variable>>(),
    );
    let context = Context::new(all_variables.clone(), all_phys_registers.clone(), graph);

    let no_alive_vars = AliveVariables::default();
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
                                    let var = all_variables.get(input_var);
                                    match var {
                                        Some(var) => alive_vars.insert(var),
                                        None => panic!(
                                            "Variable {} used at {} is not known.",
                                            input_var, jmp.tid
                                        ),
                                    }
                                }
                            }
                            _ => (),
                        }
                    }
                    computation.set_node_value(node, NodeValue::Value(alive_vars));
                } else {
                    computation.set_node_value(node, NodeValue::Value(no_alive_vars.clone()))
                }
            }
            Node::CallReturn { .. } => {
                computation.set_node_value(node, NodeValue::Value(no_alive_vars.clone()));
            }
            Node::CallSource { .. } => {
                computation.set_node_value(
                    node,
                    NodeValue::CallFlowCombinator {
                        call_stub: Some(no_alive_vars.clone()),
                        interprocedural_flow: Some(no_alive_vars.clone()),
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
                results.insert(blk.tid.clone(), alive_vars.to_owned());
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
pub fn remove_dead_var_assignments_of_block<'a>(
    block: &mut Term<Blk>,
    alive_vars_map: &HashMap<Tid, BTreeSet<&'a Variable>>,
    all_variables: &BTreeSet<&'a Variable>,
) {
    let mut alive_vars = AliveVariables::new_vars(alive_vars_map.get(&block.tid).unwrap().clone());
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
                update_alive_vars_by_def(all_variables, &mut alive_vars, def);
            }
        }
    }

    block.term.defs = cleaned_defs.into_iter().rev().collect();
}
