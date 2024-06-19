//! Calling conventions.

use crate::ghidra_pcode::ir_passes::{IrPass, SubregisterSubstitutionPass};
use crate::ghidra_pcode::{RegisterMap, Varnode};
use crate::intermediate_representation::{
    CallingConvention as IrCallingConvention, Expression as IrExpression, Variable as IrVariable,
};
use crate::utils::log::{LogMessage, WithLogs};

use serde::{Deserialize, Serialize};

/// A calling convention.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct CallingConvention {
    name: String,
    integer_parameter_register: Vec<Varnode>,
    float_parameter_register: Vec<Varnode>,
    integer_return_register: Varnode,
    float_return_register: Option<Varnode>,
    unaffected_register: Vec<Varnode>,
    killed_by_call_register: Vec<Varnode>,
}

impl CallingConvention {
    /// Returns the `idx`th integer parameter register.
    pub fn get_integer_parameter_register(&self, idx: usize) -> Option<&Varnode> {
        self.integer_parameter_register.get(idx)
    }

    /// Translates this `CallingConvention` to an IR calling convention.
    pub fn to_ir_calling_convention(
        &self,
        register_map: &RegisterMap,
    ) -> WithLogs<IrCallingConvention> {
        let mut logs = Vec::new();
        let base_reg_ir_vars = register_map.get_base_reg_ir_vars();
        let subregister_substitution_pass = SubregisterSubstitutionPass::new(register_map);

        let to_ir_vars = |vns: &Vec<Varnode>| -> Vec<IrVariable> {
            vns.iter()
                .map(|r_vn| {
                    let ir_var = r_vn.to_ir_var();

                    assert!(
                        base_reg_ir_vars.contains(&ir_var),
                        "IR var {} corresponding to reg. varnode {} is not in base reg. IR vars.
                        \n--- base_reg_ir_vars ---\n
                        {:?}
                        \n--- register_map ---\n
                        {:?}",
                        ir_var,
                        r_vn,
                        base_reg_ir_vars,
                        register_map,
                    );

                    ir_var
                })
                .collect()
        };
        let mut try_to_ir_base_var = |r_vn: &Varnode, context: &str| -> Option<IrVariable> {
            let Some(ir_var) = r_vn.try_to_ir_var() else {
                logs.push(LogMessage::new_error(format!(
                    "CallingConvention: {}: {}: Varnode '{}' cannot be converted to an IR variable.",
                    self.name, context, r_vn,
                )));
                return None;
            };
            if base_reg_ir_vars.contains(&ir_var) {
                Some(ir_var)
            } else {
                // FIXME: This is a workaround for calling conventions that use
                // subregisters for passing arguments or return values as well
                // as those for which only parts of registers are saved.
                // Instead of silently upgrading those subregisters to base
                // registers we should really be using expressions.
                logs.push(LogMessage::new_error(format!(
                    "CallingConvention: {}: {}: Varnode '{}' does not correspond to a base register. ({}, {:?})",
                    self.name,
                    context,
                    r_vn,
                    ir_var,
                    register_map.lookup_varnode(r_vn)
                )));
                Some(
                    register_map
                        .lookup_base_reg_for_varnode(r_vn)
                        .unwrap()
                        .to_ir_var(),
                )
            }
        };
        let integer_return_register =
            vec![
                try_to_ir_base_var(&self.integer_return_register, "integer_return_register")
                    .unwrap(),
            ];
        let to_ir_exprs = |vns: &Vec<Varnode>| -> Vec<IrExpression> {
            vns.iter()
                .map(|r_vn| {
                    let mut ir_expr = r_vn.to_ir_expr();

                    subregister_substitution_pass.replace_subregister_inputs(&mut ir_expr);

                    ir_expr
                })
                .collect()
        };
        let mut to_ir_base_vars = |vns: &Vec<Varnode>, context: &str| -> Vec<IrVariable> {
            vns.iter()
                // FIXME: We use `filter_map` because for some weird reason the
                // `unaffected_register`s sometimes include Varnodes that are
                // __not__ in the Register Address Space ... WTF.
                .filter_map(|r_vn| try_to_ir_base_var(r_vn, context))
                .collect()
        };

        WithLogs::new(
            IrCallingConvention {
                name: self.name.clone(),
                integer_parameter_register: to_ir_vars(&self.integer_parameter_register),
                float_parameter_register: to_ir_exprs(&self.float_parameter_register),
                integer_return_register,
                float_return_register: self
                    .float_return_register
                    .as_ref()
                    .map(|float_return_register| to_ir_exprs(&vec![float_return_register.clone()]))
                    .unwrap_or_default(),
                callee_saved_register: to_ir_base_vars(
                    &self.unaffected_register,
                    "callee_saved_register",
                ),
            },
            logs,
        )
    }
}
