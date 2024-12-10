use super::prelude::*;
use crate::intermediate_representation::*;
use crate::intermediate_representation::{Blk, Def, Term};
use std::collections::HashMap;

mod fixpoint_computation;

/// A gen-kill dataflow analysis.
///
/// - direction:        forward
/// - strategy:         must
/// - property space:   Mappings from the set of variables to expressions that
///                     those variables can be replaced with.
/// - gen:              Assignments generate an entry:
///                         assigned variable -> assigned expression
/// - kill:             - Assignments and loads kill entries whose value
///                       contains the assigned variable.
///                     - Function calls kill everything.
///                       (TODO: cases when everything is callee saved)
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
    /// Maximal height of the AST of any expression after this pass.
    const MAX_RECURSION_DEPTH: u64 = 10;

    /// Merges consecutive assignment expressions for the same variable.
    fn merge_same_var_assignments(p: &mut Program) {
        for blk in p.blocks_mut() {
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

    /// Extends the given `expression` with already known expressions in
    /// `insertable_expressions`.
    ///
    /// Ensures that the recursion depth of the returned expression
    /// is upper bounded by [`Self::MAX_RECURSION_DEPTH`].
    ///
    /// Returns `None` iff no extension is possible.
    fn extend_expression(
        expression: &Expression,
        insertable_expressions: &HashMap<Variable, Expression>,
    ) -> Option<Expression> {
        if insertable_expressions.is_empty() {
            return None;
        }

        let input_vars = expression.input_vars();
        if !input_vars
            .iter()
            .any(|invar| insertable_expressions.contains_key(invar))
        {
            return None;
        }

        let mut performed_expansion = false;
        let mut extended_expression = expression.clone();
        extended_expression.substitute_trivial_operations();
        for input_var in input_vars.into_iter() {
            if let Some(expr) = insertable_expressions.get(input_var) {
                if extended_expression.recursion_depth() + expr.recursion_depth()
                    < Self::MAX_RECURSION_DEPTH
                {
                    performed_expansion = true;
                    extended_expression.substitute_input_var(input_var, expr);
                }
            }
        }

        if performed_expansion {
            Some(extended_expression)
        } else {
            None
        }
    }

    /// Wherever possible, substitute input variables of expressions
    /// with the input expression that defines the input variable.
    ///
    /// Note that substitution is only possible
    /// if the input variables of the input expression itself did not change since the definition of said variable.
    ///
    /// The expression propagation allows more dead stores to be removed during
    /// [dead variable elimination](super::DeadVariableElimPass).
    fn propagate_input_expressions(
        blk: &mut Term<Blk>,
        apriori_insertable_expressions: Option<HashMap<Variable, Expression>>,
    ) {
        // gross
        let mut insertable_expressions = HashMap::new();
        if let Some(insertables) = apriori_insertable_expressions {
            insertable_expressions = insertables;
        }

        for d in blk.defs_mut() {
            match &mut d.term {
                Def::Assign {
                    var,
                    value: expression,
                } => {
                    if let Some(extended_expression) =
                        Self::extend_expression(expression, &insertable_expressions)
                    {
                        *expression = extended_expression;
                    } else {
                        expression.substitute_trivial_operations();
                    }

                    // GEN: Add mapping of variable to assigned expression to
                    // state.
                    insertable_expressions.insert(var.clone(), expression.clone());

                    // KILL: Expressions dependent on the assigned variable are
                    // no longer insertable.
                    insertable_expressions.retain(|_input_var, input_expr| {
                        !input_expr.input_vars().into_iter().any(|x| x == var)
                    });
                }
                Def::Load {
                    var,
                    address: expression,
                } => {
                    if let Some(extended_expression) =
                        Self::extend_expression(expression, &insertable_expressions)
                    {
                        *expression = extended_expression;
                    }

                    // KILL: Expressions dependent on the assigned variable are no
                    // longer insertable. Any replacements for the assigned
                    // variable have to be invalidated as well.
                    insertable_expressions.retain(|input_var, input_expr| {
                        input_var != var && !input_expr.input_vars().into_iter().any(|x| x == var)
                    });
                }
                Def::Store { address, value } => {
                    if let Some(extended_expression) =
                        Self::extend_expression(address, &insertable_expressions)
                    {
                        *address = extended_expression;
                    }
                    if let Some(extended_expression) =
                        Self::extend_expression(value, &insertable_expressions)
                    {
                        *value = extended_expression;
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
                    if let Some(extended_expression) =
                        Self::extend_expression(expr, &insertable_expressions)
                    {
                        *expr = extended_expression;
                    }
                }
            }
        }
    }

    /// Merge subsequent assignments to the same variable to a single assignment
    /// to that variable.
    ///
    /// In the corrent implementation, it is important to enforce a limit on the
    /// complexity of the resulting expressions.
    fn merge_def_assignments_to_same_var(b: &mut Term<Blk>) {
        let mut new_defs = Vec::new();
        let mut last_def_assign_opt = None;

        for d in b.defs_mut() {
            match &d.term {
                Def::Assign {
                    var: current_var, ..
                } => {
                    match &last_def_assign_opt {
                        Some(Term {
                            term:
                                Def::Assign {
                                    var: last_var,
                                    value: last_value,
                                },
                            ..
                        }) => {
                            if current_var != last_var {
                                new_defs.push(last_def_assign_opt.unwrap());
                                last_def_assign_opt = Some(d.clone());
                            } else {
                                let mut substituted_def = d.clone();
                                substituted_def.substitute_input_var(last_var, last_value);

                                if substituted_def.recursion_depth() < Self::MAX_RECURSION_DEPTH {
                                    last_def_assign_opt = Some(substituted_def);
                                } else {
                                    new_defs.push(last_def_assign_opt.unwrap());
                                    last_def_assign_opt = Some(d.clone());
                                }
                            }
                        }
                        // Only assign-defs should be saved in `last_def_opt`.
                        Some(..) => panic!(),
                        None => {
                            last_def_assign_opt = Some(d.clone());
                        }
                    };
                }
                Def::Store { .. } | Def::Load { .. } => {
                    if let Some(last_def) = last_def_assign_opt {
                        new_defs.push(last_def);
                    }
                    new_defs.push(d.clone());
                    last_def_assign_opt = None;
                }
            };
        }
        if let Some(last_def) = last_def_assign_opt {
            new_defs.push(last_def);
        }

        b.term.defs = new_defs;
    }
}

// TODO: Fix tests,
//#[cfg(test)]
//mod tests;
