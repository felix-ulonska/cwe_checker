use super::prelude::*;
use crate::intermediate_representation::*;
use crate::intermediate_representation::{Blk, Def, Term};
use std::collections::HashMap;

mod fixpoint_computation;

/// A gen-kill dataflow analysis.
///
/// - direction:        forward
/// - strategy:         must
/// - property space:   mappings from the set of variables to expressions that
///                     those variables can be replaced with
/// - gen:              assignments generate an entry:
///                         assigned variable -> assigned expression
/// - kill:             assignments and loads kill entries whose value contains
///                     the assigned variable
///                     function calls kill everything
///                     TODO: cases when everything is callee saved
///
/// The end result of the DFA is then used to perform the replacements.
///
/// Note: It is necessary to enforce a complexity limit on the expressions
/// in the map.
pub struct InputExpressionPropagationPass;

impl IrPass for InputExpressionPropagationPass {
    const NAME: &'static str = "InputExpressionPropagationPass";
    const DBG_IR_FORM: debug::IrForm = debug::IrForm::InputExpressionsPropagated;

    type Input = Program;
    type ConstructionInput = ();

    fn new(_construction_input: &Self::ConstructionInput) -> Self {
        Self
    }

    fn run(&mut self, program: &mut Self::Input) -> Vec<LogMessage> {
        Self::merge_same_var_assignments(program);

        let graph = crate::analysis::graph::get_program_cfg(program);
        let computation = fixpoint_computation::compute_expression_propagation(&graph);
        let results = fixpoint_computation::extract_results(&graph, computation);
        Self::insert_expressions(results, program);
        Vec::new()
    }

    fn assert_postconditions(
        _construction_input: &Self::ConstructionInput,
        _program: &Self::Input,
    ) {
    }
}

impl InputExpressionPropagationPass {
    /// Merges consecutive assignment expressions for the same variable.
    fn merge_same_var_assignments(program: &mut Program) {
        for blk in program.blocks_mut() {
            Self::merge_def_assignments_to_same_var(blk);
        }
    }

    /// Replaces for every basic block all propagated expressions.
    ///
    /// This uses the expression propagation of basic blocks, thus performs intra-basic-block insertion of expressions.
    fn insert_expressions(
        insertables: HashMap<Tid, HashMap<Variable, Expression>>,
        program: &mut Program,
    ) {
        for sub in program.subs.values_mut() {
            for block in sub.term.blocks.iter_mut() {
                Self::propagate_input_expressions(block, insertables.get(&block.tid).cloned());
            }
        }
    }
    /// Wherever possible, substitute input variables of expressions
    /// with the input expression that defines the input variable.
    ///
    /// Note that substitution is only possible
    /// if the input variables of the input expression itself did not change since the definition of said variable.
    ///
    /// The expression propagation allows more dead stores to be removed during
    /// [dead variable elimination](crate::analysis::dead_variable_elimination).
    fn propagate_input_expressions(
        blk: &mut Term<Blk>,
        apriori_insertable_expressions: Option<HashMap<Variable, Expression>>,
    ) {
        let mut insertable_expressions = HashMap::new();
        if let Some(insertables) = apriori_insertable_expressions {
            insertable_expressions = insertables;
        }
        for def in blk.term.defs.iter_mut() {
            match &mut def.term {
                Def::Assign {
                    var,
                    value: expression,
                } => {
                    // Extend the considered expression with already known expressions.
                    let mut extended_expression = expression.clone();
                    for input_var in expression.input_vars().into_iter() {
                        if let Some(expr) = insertable_expressions.get(input_var) {
                            // We limit the complexity of expressions to insert.
                            // This prevents extremely large expressions that can lead to extremely high RAM usage.
                            // FIXME: Right now this limit is quite arbitrary. Maybe there is a better way to achieve the same result?
                            if expr.recursion_depth() < 10 {
                                extended_expression.substitute_input_var(input_var, expr)
                            }
                        }
                    }
                    extended_expression.substitute_trivial_operations();
                    *expression = extended_expression;
                    // expressions dependent on the assigned variable are no longer insertable
                    insertable_expressions.retain(|input_var, input_expr| {
                        input_var != var && !input_expr.input_vars().into_iter().any(|x| x == var)
                    });
                    // If the value of the assigned variable does not depend on the former value of the variable,
                    // then it is insertable for future expressions.
                    if !expression.input_vars().into_iter().any(|x| x == var) {
                        insertable_expressions.insert(var.clone(), expression.clone());
                    }
                }
                Def::Load {
                    var,
                    address: expression,
                } => {
                    // insert known input expressions
                    for (input_var, input_expr) in insertable_expressions.iter() {
                        expression.substitute_input_var(input_var, input_expr);
                    }
                    // expressions dependent on the assigned variable are no longer insertable
                    insertable_expressions.retain(|input_var, input_expr| {
                        input_var != var && !input_expr.input_vars().into_iter().any(|x| x == var)
                    });
                }
                Def::Store { address, value } => {
                    // insert known input expressions
                    for (input_var, input_expr) in insertable_expressions.iter() {
                        address.substitute_input_var(input_var, input_expr);
                        value.substitute_input_var(input_var, input_expr);
                    }
                }
            }
        }
        for jump in blk.term.jmps.iter_mut() {
            match &mut jump.term {
                Jmp::Branch(_) | Jmp::Call { .. } | Jmp::CallOther { .. } => (),
                Jmp::BranchInd(expr)
                | Jmp::CBranch {
                    condition: expr, ..
                }
                | Jmp::CallInd { target: expr, .. }
                | Jmp::Return(expr) => {
                    // insert known input expressions
                    for (input_var, input_expr) in insertable_expressions.iter() {
                        expr.substitute_input_var(input_var, input_expr);
                    }
                }
            }
        }
    }

    /// Merge subsequent assignments to the same variable to a single assignment to that variable.
    fn merge_def_assignments_to_same_var(blk: &mut Term<Blk>) {
        let mut new_defs = Vec::new();
        let mut last_def_opt = None;
        for def in blk.term.defs.iter() {
            if let Def::Assign {
                var: current_var, ..
            } = &def.term
            {
                if let Some(Term {
                    term:
                        Def::Assign {
                            var: last_var,
                            value: last_value,
                        },
                    ..
                }) = &last_def_opt
                {
                    if current_var == last_var {
                        let mut substituted_def = def.clone();
                        substituted_def.substitute_input_var(last_var, last_value);
                        last_def_opt = Some(substituted_def);
                    } else {
                        new_defs.push(last_def_opt.unwrap());
                        last_def_opt = Some(def.clone());
                    }
                } else if last_def_opt.is_some() {
                    panic!(); // Only assign-defs should be saved in last_def.
                } else {
                    last_def_opt = Some(def.clone());
                }
            } else {
                if let Some(last_def) = last_def_opt {
                    new_defs.push(last_def);
                }
                new_defs.push(def.clone());
                last_def_opt = None;
            }
        }
        if let Some(last_def) = last_def_opt {
            new_defs.push(last_def);
        }
        blk.term.defs = new_defs;
    }
}

#[cfg(test)]
mod tests;
