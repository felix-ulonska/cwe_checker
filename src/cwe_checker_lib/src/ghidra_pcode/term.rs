use super::Instruction;
use super::PcodeOperation;

use super::ExpressionOpcode;
use super::JmpOpcode::*;
use crate::intermediate_representation::{
    Def as IrDef, Expression as IrExpression, Jmp as IrJmp, Term as IrTerm, Tid,
};

use std::fmt::{self, Display};
use std::ops::{Deref, DerefMut};

use serde::{Deserialize, Serialize};

/// A [`PcodeOperation`] at a particular place.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Term {
    address: String,
    index: u64,
    operation: PcodeOperation,
}

impl Deref for Term {
    type Target = PcodeOperation;

    fn deref(&self) -> &Self::Target {
        &self.operation
    }
}

impl DerefMut for Term {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.operation
    }
}

impl Display for Term {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:>{}:> {}", self.address, self.index, self.operation)
    }
}

impl Term {
    /// Returns the address of this term.
    pub fn address(&self) -> &String {
        &self.address
    }

    /// Returns the index of this term.
    pub fn index(&self) -> u64 {
        self.index
    }

    /// Returns true iff this is the last term of this instruction.
    ///
    /// `instr` must be the instruction that contains this term.
    fn is_last_term(&self, instr: &Instruction) -> bool {
        let num_terms = instr.terms().len() as u64;
        assert!(self.index < num_terms);

        self.index + 1 == num_terms
    }

    /// Returns the next term in this instruction.
    ///
    /// `instr` must be the instruction that contains this term.
    fn next_term<'a>(&self, instr: &'a Instruction) -> Option<&'a Self> {
        if self.is_last_term(instr) {
            None
        } else {
            Some(&instr.terms()[(self.index + 1) as usize])
        }
    }

    /// Get the jump target of a BRANCH/CBRANCH/CALL instruction as a block
    /// [`Tid`] (even in the case of a CALL).
    ///
    /// Panics for other jump types.
    /// `instr` must be the instruction that contains this term.
    fn direct_jump_get_target(&self, instr: &Instruction) -> Tid {
        assert!(self.is_direct_jump());

        if let Some(target) = self.input0().unwrap().get_ram_address_as_string() {
            Tid::new_block(target, 0)
        } else if let IrExpression::Const(jmp_offset) = self.input0().unwrap().to_ir_expr() {
            if let Some(target_index) = self
                .index
                .checked_add_signed(jmp_offset.try_to_i64().unwrap())
            {
                if instr.contains_term_index(target_index) {
                    Tid::new_block(instr.address(), target_index)
                } else {
                    Tid::new_block(
                        instr
                            .fall_through()
                            .expect("No target found for direct jump."),
                        0,
                    )
                }
            } else {
                panic!(
                    "Overflow while computing target of pcode relative jump: {}",
                    self
                );
            }
        } else {
            panic!("Could not parse direct jump target.")
        }
    }

    /// Returns the block [`Tid`]s of jump targets, including target hints for
    /// indirect calls and branches.
    ///
    /// Note that the generated [`Tid`]s are always block TIDs, even for call
    /// instructions.
    ///
    /// Panics if this is not a jump operation.
    /// `instr` must be the instruction that contains this term.
    pub fn collect_jmp_targets(&self, instr: &Instruction) -> Vec<Tid> {
        match self.unwrap_jmp_opcode() {
            BRANCH | CBRANCH | CALL => vec![self.direct_jump_get_target(instr)],
            BRANCHIND | CALLIND => {
                let mut jump_targets = vec![];
                for targets in instr.potential_targets().iter() {
                    for target in targets.iter() {
                        jump_targets.push(Tid::new_block(target, 0));
                    }
                }
                jump_targets
            }
            CALLOTHER | RETURN => Vec::new(),
        }
    }

    /// Get the fall-through address of the jump instruction, if it has one.
    ///
    /// Panics if this is not a jump operation.
    /// `instr` must be the instruction that contains this term.
    pub fn get_fall_through_target(&self, instr: &Instruction) -> Option<Tid> {
        match self.unwrap_jmp_opcode() {
            BRANCH | BRANCHIND | RETURN => None,
            CALL | CALLIND => match self.next_term(instr).map(|term| term.opcode()) {
                Some(_) => Some(Tid::new_block(instr.address(), self.index + 1)),
                None => instr
                    .fall_through()
                    .map(|fall_through_addr| Tid::new_block(fall_through_addr, 0)),
            },
            CBRANCH | CALLOTHER => {
                if !self.is_last_term(instr) {
                    Some(Tid::new_block(instr.address(), self.index + 1))
                } else {
                    instr
                        .fall_through()
                        .map(|fall_through_addr| Tid::new_block(fall_through_addr, 0))
                }
            }
        }
    }

    /// Converts ram-located input varnodes to temporary variables and returns
    /// IR Def Load terms that explicitly load into those variables.
    pub fn make_input_explicitly_loaded_and_return_ir_def_load_term_for_jump(
        &mut self,
    ) -> IrTerm<IrDef> {
        match self.unwrap_jmp_opcode() {
            BRANCHIND | CALLIND | RETURN if self.input0().is_some_and(|vn| vn.is_in_ram()) => {
                IrTerm::new(
                    Tid::new_instr_with_suffix(&self.address, self.index, Some("load0")),
                    self.input0_mut()
                        .unwrap()
                        .make_explicitly_loaded_var_and_return_ir_def_load("$load_temp0"),
                )
            }
            CBRANCH if self.input1().is_some_and(|vn| vn.is_in_ram()) => IrTerm::new(
                Tid::new_instr_with_suffix(&self.address, self.index, Some("load1")),
                self.input1_mut()
                    .unwrap()
                    .make_explicitly_loaded_var_and_return_ir_def_load("$load_temp1"),
            ),
            _ => panic!("Jump has no implicit loads."),
        }
    }

    /// Converts ram-located input varnodes to temporary variables and returns
    /// IR Def Load terms that explicitly load into those variables.
    ///
    /// The created instructions use the virtual register `$load_tempX`, whereby
    /// `X` is either `0`, `1`or `2` representing which input is used.
    /// The created `Tid` is named `instr_<address>_<pcode index>_load<X>`.
    pub fn make_inputs_explicitly_loaded_and_return_ir_def_load_terms(
        &mut self,
    ) -> Vec<IrTerm<IrDef>> {
        assert!(!self.is_jump());

        let mut explicit_loads = vec![];

        if self.input0().is_some_and(|vn| vn.is_in_ram()) {
            explicit_loads.push(IrTerm::new(
                Tid::new_instr_with_suffix(&self.address, self.index, Some("load0")),
                self.input0_mut()
                    .unwrap()
                    .make_explicitly_loaded_var_and_return_ir_def_load("$load_temp0"),
            ));
        }
        if self.input1().is_some_and(|vn| vn.is_in_ram()) {
            let tid = Tid::new_instr_with_suffix(&self.address, self.index, Some("load1"));
            explicit_loads.push(IrTerm::new(
                tid,
                self.input1_mut()
                    .unwrap()
                    .make_explicitly_loaded_var_and_return_ir_def_load("$load_temp1"),
            ));
        }
        if self.input2().is_some_and(|vn| vn.is_in_ram()) {
            let tid = Tid::new_instr_with_suffix(&self.address, self.index, Some("load2"));
            explicit_loads.push(IrTerm::new(
                tid,
                self.input2_mut()
                    .unwrap()
                    .make_explicitly_loaded_var_and_return_ir_def_load("$load_temp2"),
            ));
        }

        explicit_loads
    }

    /// Translates a jump operation into a [`IrJmp`] term.
    ///
    /// Prepends additional [`IrDef::Load`] terms, if the pcode operation
    /// performs implicit loads from ram.
    ///
    /// Panics if the term is not a jump operation.
    /// `instr` must be the instruction that contains this term.
    pub fn to_ir_jump_term(&self, instr: &Instruction) -> IrTerm<IrJmp> {
        assert!(!self.operation.uses_stack_varnode());

        let jump = match self.unwrap_jmp_opcode() {
            BRANCH => self.to_ir_jmp_branch(self.direct_jump_get_target(instr)),
            CBRANCH => self.to_ir_jmp_cbranch(self.direct_jump_get_target(instr)),
            BRANCHIND => self.to_ir_jmp_branch_ind(),
            CALL => self.to_ir_jmp_call(self.get_fall_through_target(instr)),
            CALLIND => self.to_ir_jmp_call_ind(self.get_fall_through_target(instr)),
            CALLOTHER => {
                self.to_ir_jmp_call_other(self.get_fall_through_target(instr), instr.mnemonic())
            }
            RETURN => self.to_ir_jmp_return(),
        };

        IrTerm::new(Tid::new_instr(&self.address, self.index), jump)
    }

    /// Translates an expression operation into at least one [`IrDef`] term.
    ///
    /// Prepends additional [`IrDef::Load`] terms, if the pcode operation
    /// performs implicit loads from ram.
    ///
    /// Panics if the operation is not an expression operation.
    pub fn to_ir_def_terms(&self) -> Vec<IrTerm<IrDef>> {
        assert!(!self.operation.uses_stack_varnode());

        let mut ir_terms = vec![];

        if self.has_implicit_load() {
            let mut term_to_convert = self.clone();

            let mut explicit_loads =
                term_to_convert.make_inputs_explicitly_loaded_and_return_ir_def_load_terms();
            ir_terms.append(&mut explicit_loads);

            if let Some(ir_term) = term_to_convert.to_ir_def_term_no_implicit_load() {
                ir_terms.push(ir_term);
            }
        } else if self.is_ghidra_unimplemented() {
            // We silently ignore instructions that are not implemented in
            // Ghidra. Happens only for exotic arches, e.g., m68k.
        } else if let Some(ir_term) = self.to_ir_def_term_no_implicit_load() {
            ir_terms.push(ir_term);
        }

        ir_terms
    }

    fn to_ir_def_term_no_implicit_load(&self) -> Option<IrTerm<IrDef>> {
        assert!(!self.has_implicit_load());

        let ir_def = match self.unwrap_expr_opcode() {
            ExpressionOpcode::LOAD => self.to_ir_def_load(),
            ExpressionOpcode::STORE => self.to_ir_def_store(),
            ExpressionOpcode::COPY => self.to_ir_def_assign(),
            ExpressionOpcode::SUBPIECE => self.to_ir_def_subpiece(),
            expr_type if expr_type.is_ir_unop() => self.to_ir_def_unop(),
            expr_type if expr_type.is_ir_biop() => self.to_ir_def_biop(),
            expr_type if expr_type.is_ir_cast() => self.to_ir_def_castop(),
            _ => panic!(
                "Unexpected pcode expression operator while translating: {}",
                self
            ),
        };

        ir_def.map(|ir_def| IrTerm {
            tid: Tid::new_instr(&self.address, self.index),
            term: ir_def,
        })
    }
}
