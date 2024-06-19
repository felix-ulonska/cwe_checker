use super::prelude::*;

use crate::ghidra_pcode::{RegisterMap, RegisterProperties};
use crate::intermediate_representation::{
    Arg as IrArg, Blk as IrBlk, Def as IrDef, Expression as IrExpression,
    ExternSymbol as IrExternSymbol, Jmp as IrJmp, Term as IrTerm, Variable as IrVariable,
};

use std::collections::BTreeSet;
use std::ops::Deref;

/// # Register Model
///
/// This is a braindump of our toy model for registers in Pcode.
///
/// We model the named CPU registers as a poset `R`. The partial order is
/// defined based on containment in the Register Address Space.
///
/// We assume that this poset has the following properties:
///
/// "Base Register Property":
///     Let `upper(r)` denote the set of all upper bounds of the register `r`.
///     Then, we assume that `base(r) := join(upper(r))` exists.
///     - A register `r` for which `base(r) == r` is called base register.
///     - A register `r` for which `base(r) != r` is called subregister.
/// "Parent Register Property":
///     Let `cover(r)` denote the set of all registers that cover `r`.
///     Then, `|cover(r)| = 1` and `parent(r) := meet(upper(r) / {r})` is the
///     single element.
///
/// We extend the register poset with arbitrary slices of named registers.
/// (The partial order extends in the obvious way.)
/// Lets call the extended poset `Ext(r)`.
/// - We assume that the Base Register Property holds in the extended set if it
///   holds in the base set.
///   - This implies that the base registers `r in R: r == base(r)` are
///     independent, i.e., they do not overlap in the Register Address Space.
/// - The Parent Register Property continues to hold when we replace
///   `cover -> cover_named` and `upper -> upper_named`, i.e., we only consider
///   elements in the sub-poset of named registers when forming these sets.
///
/// Within the extended poset we have that for each `r in R` there is a unique
/// `s in Ext(R) \ R` that describes the same thing. To remove this redundancy
/// we introduce an equivalence relation `~` and define the canonical extended
/// register set `CExt(R) := Ext(R) \ ~`.
///
/// Going to the canonical extended poset gives us the following relation
/// between IR variables and elements in `CExt(R)`:
/// - Each non-temporary IR variable corresponds to a unique element in the
///   canonical extended poset, i.e., there is a function
///   `p: NtIrVar -> CExt(R)`.
///
/// The idea of the subregister substitution is to replace each occurrence of
/// registers `r in CExt(R): r != base(r)` with their base register. This is to
/// simplify value-tracking.
///
/// - For expressions, all input subregisters are replaced by slices (SUBPIECEs)
///   of the respective base register.
/// - For assignments to subregisters, the lhs of the assignment is changed to
///   the base register and the rhs expression is extended by pieces of the base
///   register.
/// - For loads into subregisters, a temporary variable is introduces to hold
///   the loaded value and then the assignment of the loaded value to the
///   subregister is processed.
///
/// # Guarantees
///
/// Should not iterfere with any other pass.
///
/// # Postconditions
///
/// 1. For all non-temporary IR variables `v` that appear in the program `P` it
///    holds that `base(p(v)) == p(v)`.
///
/// # Run After
pub struct SubregisterSubstitutionPass<'a> {
    register_map: RegisterMap<'a>,
}

impl<'a> IrPass for SubregisterSubstitutionPass<'a> {
    const NAME: &'static str = "SubregisterSubstitutionPass";
    const DBG_IR_FORM: debug::IrForm = debug::IrForm::SubregistersSubstituted;

    type Input = Program;
    type ConstructionInput = RegisterMap<'a>;

    fn new(register_map: &Self::ConstructionInput) -> Self {
        Self {
            register_map: register_map.clone(),
        }
    }

    fn run(&mut self, program: &mut Self::Input) -> Vec<LogMessage> {
        for block in program.blocks_mut() {
            self.process_block(&mut block.term);
        }

        for ext_fn in program.extern_symbols.values_mut() {
            self.process_ext_fn(ext_fn);
        }

        Vec::new()
    }

    /// Asserts that all physical registers that appear in the program are
    /// base registers, i.e., that the subregister substitution was exhaustive.
    fn assert_postconditions(register_map: &Self::ConstructionInput, program: &Self::Input) {
        let pass = Self::new(register_map);

        let base_reg_ir_vars = pass.register_map.get_base_reg_ir_vars();

        for ext_fn in program.extern_symbols.values() {
            for param_or_retval in ext_fn.parameters.iter().chain(ext_fn.return_values.iter()) {
                match param_or_retval {
                    IrArg::Stack { address: expr, .. } | IrArg::Register { expr, .. } => {
                        dbg_assert_phys_input_vars_in(expr, &base_reg_ir_vars)
                    }
                }
            }
        }

        for block in program.blocks() {
            for jmp in block.term.jmps.iter() {
                match &jmp.term {
                    IrJmp::BranchInd(expr)
                    | IrJmp::CBranch {
                        condition: expr, ..
                    }
                    | IrJmp::CallInd { target: expr, .. }
                    | IrJmp::Return(expr) => dbg_assert_phys_input_vars_in(expr, &base_reg_ir_vars),
                    IrJmp::Branch(_) | IrJmp::Call { .. } | IrJmp::CallOther { .. } => (),
                }
            }
            for def in block.term.defs.iter() {
                match &def.term {
                    IrDef::Load { var, address: expr } | IrDef::Assign { var, value: expr } => {
                        if var.is_physical_register() {
                            assert!(base_reg_ir_vars.contains(var));
                        }
                        dbg_assert_phys_input_vars_in(expr, &base_reg_ir_vars);
                    }
                    IrDef::Store { address, value } => {
                        dbg_assert_phys_input_vars_in(address, &base_reg_ir_vars);
                        dbg_assert_phys_input_vars_in(value, &base_reg_ir_vars);
                    }
                }
            }
        }
    }
}

impl<'a> SubregisterSubstitutionPass<'a> {
    fn process_ext_fn(&self, ext_fn: &mut IrExternSymbol) {
        for param_or_retval in ext_fn
            .parameters
            .iter_mut()
            .chain(ext_fn.return_values.iter_mut())
        {
            match param_or_retval {
                IrArg::Stack { address: expr, .. } | IrArg::Register { expr, .. } => {
                    self.replace_subregister_inputs(expr)
                }
            }
        }
    }

    fn process_block(&self, block: &mut IrBlk) {
        // In-place modification possible but not worth the code complexity.
        block.defs = self.process_defs(&block.defs);

        for jmp in block.jmps.iter_mut() {
            self.process_jump(&mut jmp.term)
        }
    }

    fn process_defs(&self, defs: &[IrTerm<IrDef>]) -> Vec<IrTerm<IrDef>> {
        let mut defs_iter = defs.iter().peekable();
        let mut new_defs = Vec::new();

        while let (Some(def), next_def) = (defs_iter.next(), defs_iter.peek()) {
            let mut new_def = def.clone();

            match &mut new_def.term {
                IrDef::Assign { var, value } => {
                    // At this point, the code should be in a form where variables
                    // being assigned and values that are assigned are of the same
                    // size.
                    debug_assert_eq!(
                        var.size,
                        value.bytesize(),
                        "Encountered invalid assignment: variable {} has size {} vs. value {} has size {}.",
                        var,
                        var.size,
                        value,
                        value.bytesize()
                    );

                    self.replace_subregister_inputs(value);

                    // Assignment to subregister.
                    if let Some(base_reg_slice) = self
                        .register_map
                        .get_proper_base_reg_slice_for_ir_variable(var)
                    {
                        // Chance to fold two terms.
                        if next_def.is_some_and(|next_def| {
                            self.is_cast_to(var, base_reg_slice.register(), &next_def.term)
                        }) {
                            // This catches a very specific pattern that occurs
                            // often enough to care about it (TODO: does it?).
                            //
                            // r = e
                            // base(r) = <cast_op>(r)
                            //
                            // where `r` is a subregister. This can obviously be
                            // simplified to
                            //
                            // base(r) = <cast_op>(r)
                            //
                            // and that is what is supposed to happen here.
                            let mut cast_to_base_def = defs_iter.next().unwrap().clone();
                            let IrDef::Assign {
                                value: cast_val, ..
                            } = &mut cast_to_base_def.term
                            else {
                                unreachable!();
                            };

                            cast_val.substitute_input_var(var, value);

                            new_defs.push(cast_to_base_def)
                        } else {
                            *var = base_reg_slice.register().to_ir_var();
                            *value = base_reg_slice.expand_to_full_size_expr(value);

                            new_defs.push(new_def)
                        }
                    } else {
                        new_defs.push(new_def)
                    }
                }
                IrDef::Load { var, address } => {
                    self.replace_subregister_inputs(address);

                    // Load into subregister.
                    if let Some(base_reg_slice) = self
                        .register_map
                        .get_proper_base_reg_slice_for_ir_variable(var)
                    {
                        let temp_reg = IrVariable {
                            name: "loaded_value".to_string(),
                            size: var.size,
                            is_temp: true,
                        };

                        // Chance to avoid the introduction of an extra term.
                        if next_def.is_some_and(|next_def| {
                            self.is_cast_to(var, base_reg_slice.register(), &next_def.term)
                        }) {
                            // Similar to above. Here, the pattern is:
                            //
                            // r = load e
                            // base(r) = <cast_op>(r)
                            //
                            // where `r` is a subregister. This can obviously be
                            // simplified to
                            //
                            // tmp = load a
                            // base(r) = <cast_op>(tmp)
                            let mut cast_to_base_def = defs_iter.next().unwrap().clone();
                            let IrDef::Assign {
                                value: cast_val, ..
                            } = &mut cast_to_base_def.term
                            else {
                                unreachable!();
                            };

                            cast_val
                                .substitute_input_var(var, &IrExpression::Var(temp_reg.clone()));

                            // Make this def load into the temporary register ...
                            *var = temp_reg;
                            new_defs.push(new_def);

                            // ... and then directly use it in the follow-up
                            // cast term.
                            new_defs.push(cast_to_base_def);
                        } else {
                            // Make this def load into the temporary register ...
                            *var = temp_reg.clone();
                            new_defs.push(new_def);

                            // ... and then assign the temporary register to the
                            // full one.
                            let assignment = IrDef::Assign {
                                var: base_reg_slice.register().to_ir_var(),
                                value: base_reg_slice
                                    .expand_to_full_size_expr(&IrExpression::Var(temp_reg)),
                            };
                            new_defs.push(IrTerm::new(
                                def.tid.clone().with_id_suffix("_cast_to_base"),
                                assignment,
                            ));
                        }
                    } else {
                        new_defs.push(new_def);
                    }
                }
                IrDef::Store { address, value } => {
                    self.replace_subregister_inputs(address);
                    self.replace_subregister_inputs(value);

                    new_defs.push(new_def)
                }
            }
        }

        new_defs
    }

    fn process_jump(&self, jump: &mut IrJmp) {
        match jump {
            IrJmp::BranchInd(expr)
            | IrJmp::CBranch {
                condition: expr, ..
            }
            | IrJmp::CallInd { target: expr, .. }
            | IrJmp::Return(expr) => {
                self.replace_subregister_inputs(expr);
            }
            IrJmp::Branch(_) | IrJmp::Call { .. } | IrJmp::CallOther { .. } => (),
        }
    }

    /// Returns true iff `def` is of the form `reg = <cast_op>(var)`.
    fn is_cast_to(&self, var: &IrVariable, reg: &RegisterProperties, def: &IrDef) -> bool {
        let IrDef::Assign {
            var: assigned_var,
            value,
        } = &def
        else {
            return false;
        };
        if !self
            .register_map
            .lookup_ir_variable_unique(assigned_var)
            .is_some_and(|assigned_reg| assigned_reg == reg)
        {
            return false;
        }
        let IrExpression::Cast { arg, .. } = value else {
            return false;
        };
        let IrExpression::Var(cast_var) = arg.deref() else {
            return false;
        };

        cast_var == var
    }

    /// Replaces all inputs of `expr` that are subregisters with SUBPIECE
    /// expressions over the corresponding base register.
    pub fn replace_subregister_inputs(&self, expr: &mut IrExpression) {
        let replacement_pairs: Vec<(IrVariable, IrExpression)> = expr
            .input_vars()
            .iter()
            .filter_map(|var| {
                self.register_map
                    .get_proper_base_reg_slice_for_ir_variable(var)
                    .map(|slice| ((*var).clone(), slice.to_ir_subpiece_expr()))
            })
            .collect();

        for (input_var, replacement_expr) in replacement_pairs {
            expr.substitute_input_var(&input_var, &replacement_expr);
        }
    }
}

/// Asserts that all physical input registers to `expr` are in the set
/// `vars`.
fn dbg_assert_phys_input_vars_in(expr: &IrExpression, vars: &BTreeSet<IrVariable>) {
    for input_var in expr
        .input_vars()
        .iter()
        .filter(|input_var| input_var.is_physical_register())
    {
        debug_assert!(vars.contains(input_var));
    }
}

#[cfg(test)]
mod tests;
