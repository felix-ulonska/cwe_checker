//! Pcode operations.

use super::*;
use crate::intermediate_representation::{Def as IrDef, Expression as IrExpression};

use std::fmt::{self, Display};

use serde::{Deserialize, Serialize};

mod jumps;

/// A pcode operation.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct PcodeOperation {
    /// Opcode of this operation.
    // TODO: Rename to `opcode`.
    pcode_mnemonic: PcodeOpcode,
    /// Fist input varnode.
    input0: Option<Varnode>,
    /// Second input varnode.
    input1: Option<Varnode>,
    /// Third input varnode.
    input2: Option<Varnode>,
    /// Output varnode.
    output: Option<Varnode>,
}

impl Display for PcodeOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(input0) = &self.input0 {
            write!(f, "({}", input0)?;
        }
        if let Some(input1) = &self.input1 {
            write!(f, ", {}", input1)?;
        }
        if let Some(input2) = &self.input2 {
            assert!(self.input1.is_some());
            write!(f, ", {}", input2)?;
        }
        write!(f, ")")?;
        write!(f, " {}", self.pcode_mnemonic)?;
        if let Some(output) = &self.output {
            write!(f, " -> {}", output)?;
        }

        Ok(())
    }
}

impl PcodeOperation {
    /// Returns true iff any of the varnodes used by this operation are in the
    /// "stack" address space.
    ///
    /// Note: Varnodes with this address space are only expected as parameter
    /// locations for external functions.
    pub fn uses_stack_varnode(&self) -> bool {
        self.input0().is_some_and(|vn| vn.is_in_stack())
            || self.input1().is_some_and(|vn| vn.is_in_stack())
            || self.input2().is_some_and(|vn| vn.is_in_stack())
            || self.output().is_some_and(|vn| vn.is_in_stack())
    }

    /// Returns the number of input varnodes for this operation.
    pub fn num_inputs(&self) -> u8 {
        let mut num_inputs = 1;

        if self.input1().is_some() {
            num_inputs += 1;
        }
        if self.input2().is_some() {
            num_inputs += 1;
        }

        num_inputs
    }

    /// Returns the opcode of this operation.
    pub fn opcode(&self) -> &PcodeOpcode {
        &self.pcode_mnemonic
    }

    /// Returns true iff this operation is not implemented in Ghidra.
    pub fn is_ghidra_unimplemented(&self) -> bool {
        matches!(
            self.opcode(),
            PcodeOpcode::Expression(ExpressionOpcode::UNIMPLEMENTED)
        )
    }

    /// Returns the first input varnode to this operation.
    pub fn input0(&self) -> Option<&Varnode> {
        self.input0.as_ref()
    }

    /// Returns the second input varnode to this operation.
    pub fn input1(&self) -> Option<&Varnode> {
        self.input1.as_ref()
    }

    /// Returns the third input varnode to this operation.
    pub fn input2(&self) -> Option<&Varnode> {
        self.input2.as_ref()
    }

    /// Returns the first input varnode to this operation.
    pub fn input0_mut(&mut self) -> Option<&mut Varnode> {
        self.input0.as_mut()
    }

    /// Returns the second input varnode to this operation.
    pub fn input1_mut(&mut self) -> Option<&mut Varnode> {
        self.input1.as_mut()
    }

    /// Returns the third input varnode to this operation.
    pub fn input2_mut(&mut self) -> Option<&mut Varnode> {
        self.input2.as_mut()
    }

    /// Returns the output varnode of this operation.
    pub fn output(&self) -> Option<&Varnode> {
        self.output.as_ref()
    }

    /// Helper function to unwrap the expression opcode of a pcode operation.
    ///
    /// Panics if `self` is not an expression.
    pub fn unwrap_expr_opcode(&self) -> ExpressionOpcode {
        match self.opcode() {
            PcodeOpcode::Expression(expr_type) => *expr_type,
            _ => panic!("Term was not an expression operation."),
        }
    }

    /// Returns `true` if at least one input is ram located.
    ///
    /// Panics if `self` is not an expression.
    pub fn has_implicit_load(&self) -> bool {
        assert!(!self.is_jump());

        self.input0().is_some_and(|vn| vn.is_in_ram())
            || self.input1().is_some_and(|vn| vn.is_in_ram())
            || self.input2().is_some_and(|vn| vn.is_in_ram())
    }

    /// Returns `true` iff the target address is ram located.
    ///
    /// Panics if `self` is an expression.
    pub fn has_implicit_load_for_jump(&self) -> bool {
        use crate::ghidra_pcode::JmpOpcode::*;
        match self.unwrap_jmp_opcode() {
            BRANCHIND | CALLIND | RETURN => self.input0().is_some_and(|vn| vn.is_in_ram()),
            CBRANCH => self.input1().is_some_and(|varnode| varnode.is_in_ram()),
            _ => false,
        }
    }

    /// Returns `true` if the output is ram located.
    ///
    /// Panics if `self` is not an expression.
    pub fn has_implicit_store(&self) -> bool {
        assert!(!self.is_jump());

        self.output().is_some_and(|varnode| varnode.is_in_ram())
    }

    /// Translates Pcode `LOAD` to [`IrDef`] containing [`IrDef::Load`].
    ///
    /// Note: input0 ("Constant ID of space to load from") is not considered.
    ///
    /// Returns `None` iff this operation is equivalent to a NOP in the
    /// intermediate representation.
    pub fn to_ir_def_load(&self) -> Option<IrDef> {
        assert!(matches!(
            self.opcode(),
            PcodeOpcode::Expression(ExpressionOpcode::LOAD)
        ));
        assert_eq!(self.num_inputs(), 2);
        assert!(self.output().is_some());

        let IrExpression::Var(var) = self.output().expect("Load without output.").to_ir_expr()
        else {
            panic!("Load target is not a variable: {}", self)
        };
        let source = self.input1().expect("Load without source.").to_ir_expr();

        Some(IrDef::Load {
            var,
            address: source,
        })
    }

    /// Translates Pcode `STORE` to [`IrDef`] containing [`IrDef::Store`].
    ///
    /// Note: input0 ("Constant ID of space to store into") is not considered.
    ///
    /// Returns `None` iff this operation is equivalent to a NOP in the
    /// intermediate representation.
    pub fn to_ir_def_store(&self) -> Option<IrDef> {
        assert!(matches!(
            self.opcode(),
            PcodeOpcode::Expression(ExpressionOpcode::STORE)
        ));
        assert_eq!(self.num_inputs(), 3);
        assert!(self.output().is_none());

        let target_expr = self.input1().expect("Store without target.").to_ir_expr();

        let data = self.input2().expect("Store without source data.");
        assert!(
            data.is_in_const() || data.is_in_unique() || data.is_in_register(),
            "Store source data is not a register, temp variable or constant."
        );
        let source_expr = data.to_ir_expr();

        Some(IrDef::Store {
            address: target_expr,
            value: source_expr,
        })
    }

    /// Translates Pcode `SUBPIECE` to [`IrDef`] containing
    /// [`IrExpression::Subpiece`].
    ///
    /// Returns `None` iff this operation is equivalent to a NOP in the
    /// intermediate representation.
    pub fn to_ir_def_subpiece(&self) -> Option<IrDef> {
        assert!(matches!(
            self.opcode(),
            PcodeOpcode::Expression(ExpressionOpcode::SUBPIECE)
        ));
        assert_eq!(self.num_inputs(), 2);
        assert!(self.output().is_some());

        let IrExpression::Const(truncate) = self
            .input1()
            .expect("input1 of subpiece is None.")
            .to_ir_expr()
        else {
            panic!("Number of truncation bytes is not a constant: {}", self)
        };
        let ir_expr = IrExpression::Subpiece {
            low_byte: truncate.try_to_u64().unwrap().into(),
            size: self
                .output()
                .expect("Subpiece output is None.")
                .size()
                .into(),
            arg: Box::new(self.input0().unwrap().to_ir_expr()),
        };

        self.wrap_in_ir_def_assign_or_store(ir_expr)
    }

    /// Translates Pcode `COPY` to [`IrDef`] containing [`IrDef::Assign`].
    ///
    /// Returns `None` iff this operation is equivalent to a NOP in the
    /// intermediate representation.
    pub fn to_ir_def_assign(&self) -> Option<IrDef> {
        assert!(matches!(
            self.opcode(),
            PcodeOpcode::Expression(ExpressionOpcode::COPY)
        ));
        assert_eq!(self.num_inputs(), 1);
        assert!(self.output().is_some());

        let ir_expr = self.input0().unwrap().to_ir_expr();

        self.wrap_in_ir_def_assign_or_store(ir_expr)
    }

    /// Translates a pcode operation with one input into an [`IrDef`] containing
    /// an [`IrExpression::UnOp`].
    ///
    /// The mapping is implemented in [`ExpressionOpcode::try_to_ir_unop`].
    ///
    /// Returns `None` iff this operation is equivalent to a NOP in the
    /// intermediate representation.
    pub fn to_ir_def_unop(&self) -> Option<IrDef> {
        assert_eq!(self.num_inputs(), 1);
        assert!(self.output().is_some());

        let PcodeOpcode::Expression(expr_type) = self.opcode() else {
            panic!("Not an expression type: {}", self)
        };
        let ir_expr = IrExpression::UnOp {
            op: expr_type
                .try_to_ir_unop()
                .expect("Translation into unary operation failed."),
            arg: Box::new(self.input0().unwrap().to_ir_expr()),
        };

        self.wrap_in_ir_def_assign_or_store(ir_expr)
    }

    /// Translates a Pcode operation with two inputs into an [`IrDef`]
    /// containing an [`IrExpression::BinOp`].
    ///
    /// The mapping is implemented in [`ExpressionOpcode::try_to_ir_biop`].
    ///
    /// Returns `None` iff this operation is equivalent to a NOP in the
    /// intermediate representation.
    pub fn to_ir_def_biop(&self) -> Option<IrDef> {
        assert_eq!(self.num_inputs(), 2);
        assert!(self.output().is_some());

        let PcodeOpcode::Expression(expr_type) = self.opcode() else {
            panic!("Not an expression type: {}", self)
        };
        let ir_expr = IrExpression::BinOp {
            op: expr_type
                .try_to_ir_biop()
                .expect("Translation into binary operation failed."),
            lhs: Box::new(self.input0().unwrap().to_ir_expr()),
            rhs: Box::new(
                self.input1()
                    .expect("No `input1` for binary operation.")
                    .to_ir_expr(),
            ),
        };

        self.wrap_in_ir_def_assign_or_store(ir_expr)
    }

    /// Translates a cast pcode operation into an [`IrDef`] with
    /// [`IrExpression::Cast`].
    ///
    /// The mapping is implemented in [`ExpressionOpcode::try_to_ir_cast`].
    ///
    /// Returns `None` iff this operation is equivalent to a NOP in the
    /// intermediate representation.
    pub fn to_ir_def_castop(&self) -> Option<IrDef> {
        assert!(self.output().is_some());
        assert_eq!(self.num_inputs(), 1);

        let PcodeOpcode::Expression(expr_type) = self.opcode() else {
            panic!("Not an expression type: {}", self)
        };
        let ir_expr = IrExpression::Cast {
            op: expr_type
                .try_to_ir_cast()
                .expect("Translation into cast operation failed."),
            size: self
                .output()
                .expect("No output for cast operation.")
                .size()
                .into(),
            arg: Box::new(self.input0().unwrap().to_ir_expr()),
        };

        self.wrap_in_ir_def_assign_or_store(ir_expr)
    }

    /// Creates an [`IrDef::Assign`] or [`IrDef::Store`] operation depending on
    /// whether an implicit memory write is performed.
    ///
    /// Returns `None` iff the expression is assigned to a Varnode in the
    /// constant address space.
    fn wrap_in_ir_def_assign_or_store(&self, ir_expr: IrExpression) -> Option<IrDef> {
        if self.has_implicit_store() {
            Some(IrDef::Store {
                address: IrExpression::Const(
                    self.output()
                        .expect("No output varnode.")
                        .get_ram_address()
                        .expect("Unable to translate operation: {} (Output varnode is not ram.)"),
                ),
                value: ir_expr,
            })
        } else {
            match self
                .output()
                .expect("Unable to translate operation: {} (No output varnode.)")
                .to_ir_expr()
            {
                IrExpression::Var(var) => Some(IrDef::Assign {
                    var,
                    value: ir_expr,
                }),
                IrExpression::Const(_) => {
                    // The semantics of assignments to Varnodes in the constant
                    // address space are that the result is discarded. As the
                    // evaluation of IrExpressions is side effect free we can
                    // completely discard this term.
                    None
                }
                _ => panic!(
                    "Unable to translate operation: {} (Output varnode in illegal address space.)",
                    self
                ),
            }
        }
    }
}

// TODO: Fix tests.
//#[cfg(test)]
//pub mod tests;
