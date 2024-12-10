//! Pcode opcodes.

use crate::intermediate_representation::{
    BinOpType as IrBinOpType, CastOpType as IrCastOpType, UnOpType as IrUnOpType,
};

use std::fmt::{self, Display};

use serde::{Deserialize, Serialize};

/// Pcode opcode wrapper.
///
/// Wrapps expression and jump opcodes for direct deserialization.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
#[serde(untagged)]
pub enum PcodeOpcode {
    Expression(ExpressionOpcode),
    Jump(JmpOpcode),
}

impl Display for PcodeOpcode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PcodeOpcode::Jump(j) => write!(f, "Jmp({})", j),
            PcodeOpcode::Expression(e) => write!(f, "Expr({})", e),
        }
    }
}

/// Pcode expression opcodes.
#[allow(missing_docs)]
#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum ExpressionOpcode {
    COPY,
    LOAD,
    STORE,
    PIECE,
    SUBPIECE,
    POPCOUNT,
    LZCOUNT,

    INT_EQUAL,
    INT_NOTEQUAL,
    INT_LESS,
    INT_SLESS,
    INT_LESSEQUAL,
    INT_SLESSEQUAL,

    INT_ADD,
    INT_SUB,
    INT_CARRY,
    INT_SCARRY,
    INT_SBORROW,

    INT_XOR,
    INT_AND,
    INT_OR,

    INT_LEFT,
    INT_RIGHT,
    INT_SRIGHT,

    INT_MULT,
    INT_DIV,
    INT_REM,
    INT_SDIV,
    INT_SREM,

    BOOL_XOR,
    BOOL_AND,
    BOOL_OR,

    FLOAT_EQUAL,
    FLOAT_NOTEQUAL,
    FLOAT_LESS,
    FLOAT_LESSEQUAL,

    FLOAT_ADD,
    FLOAT_SUB,
    FLOAT_MULT,
    FLOAT_DIV,

    INT_NEGATE,
    INT_2COMP,
    BOOL_NEGATE,

    FLOAT_NEG,
    FLOAT_ABS,
    FLOAT_SQRT,
    #[serde(alias = "CEIL")]
    FLOAT_CEIL,
    #[serde(alias = "FLOOR")]
    FLOAT_FLOOR,
    #[serde(alias = "ROUND")]
    FLOAT_ROUND,
    FLOAT_NAN,

    INT_ZEXT,
    INT_SEXT,
    INT2FLOAT,
    FLOAT2FLOAT,
    TRUNC,

    UNIMPLEMENTED,
}

impl Display for ExpressionOpcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ExpressionOpcode::*;
        match self {
            COPY => write!(f, "COPY"),
            LOAD => write!(f, "LOAD"),
            STORE => write!(f, "STORE"),
            PIECE => write!(f, "PIECE"),
            SUBPIECE => write!(f, "SUBPIECE"),
            POPCOUNT => write!(f, "POPCOUNT"),
            LZCOUNT => write!(f, "LZCOUNT"),
            INT_EQUAL => write!(f, "INT_EQUAL"),
            INT_NOTEQUAL => write!(f, "INT_NOTEQUAL"),
            INT_LESS => write!(f, "INT_LESS"),
            INT_SLESS => write!(f, "INT_SLESS"),
            INT_LESSEQUAL => write!(f, "INT_LESSEQUAL"),
            INT_SLESSEQUAL => write!(f, "INT_SLESSEQUAL"),
            INT_ADD => write!(f, "INT_ADD"),
            INT_SUB => write!(f, "INT_SUB"),
            INT_CARRY => write!(f, "INT_CARRY"),
            INT_SCARRY => write!(f, "INT_SCARRY"),
            INT_SBORROW => write!(f, "INT_SBORROW"),
            INT_XOR => write!(f, "INT_XOR"),
            INT_AND => write!(f, "INT_AND"),
            INT_OR => write!(f, "INT_OR"),
            INT_LEFT => write!(f, "INT_LEFT"),
            INT_RIGHT => write!(f, "INT_RIGHT"),
            INT_SRIGHT => write!(f, "INT_SRIGHT"),
            INT_MULT => write!(f, "INT_MULT"),
            INT_DIV => write!(f, "INT_DIV"),
            INT_REM => write!(f, "INT_REM"),
            INT_SDIV => write!(f, "INT_SDIV"),
            INT_SREM => write!(f, "INT_SREM"),
            BOOL_XOR => write!(f, "BOOL_XOR"),
            BOOL_AND => write!(f, "BOOL_AND"),
            BOOL_OR => write!(f, "BOOL_OR"),
            FLOAT_EQUAL => write!(f, "FLOAT_EQUAL"),
            FLOAT_NOTEQUAL => write!(f, "FLOAT_NOTEQUAL"),
            FLOAT_LESS => write!(f, "FLOAT_LESS"),
            FLOAT_LESSEQUAL => write!(f, "FLOAT_LESSEQUAL"),
            FLOAT_ADD => write!(f, "FLOAT_ADD"),
            FLOAT_SUB => write!(f, "FLOAT_SUB"),
            FLOAT_MULT => write!(f, "FLOAT_MULT"),
            FLOAT_DIV => write!(f, "FLOAT_DIV"),
            INT_NEGATE => write!(f, "INT_NEGATE"),
            INT_2COMP => write!(f, "INT_2COMP"),
            BOOL_NEGATE => write!(f, "BOOL_NEGATE"),
            FLOAT_NEG => write!(f, "FLOAT_NEG"),
            FLOAT_ABS => write!(f, "FLOAT_ABS"),
            FLOAT_SQRT => write!(f, "FLOAT_SQRT"),
            FLOAT_CEIL => write!(f, "FLOAT_CEIL"),
            FLOAT_FLOOR => write!(f, "FLOAT_FLOOR"),
            FLOAT_ROUND => write!(f, "FLOAT_ROUND"),
            FLOAT_NAN => write!(f, "FLOAT_NAN"),
            INT_ZEXT => write!(f, "INT_ZEXT"),
            INT_SEXT => write!(f, "INT_SEXT"),
            INT2FLOAT => write!(f, "INT2FLOAT"),
            FLOAT2FLOAT => write!(f, "FLOAT2FLOAT"),
            TRUNC => write!(f, "TRUNC"),
            UNIMPLEMENTED => write!(f, "UNIMPLEMENTED"),
        }
    }
}

impl ExpressionOpcode {
    /// Returns true iff this opcode is a unary, non-casting operator.
    pub fn is_ir_unop(&self) -> bool {
        self.try_to_ir_unop().is_some()
    }

    /// Returns true iff this opcode is a binary, non-casting operator.
    pub fn is_ir_biop(&self) -> bool {
        self.try_to_ir_biop().is_some()
    }

    /// Returns true iff this opcode is a unary, casting operator.
    pub fn is_ir_cast(&self) -> bool {
        self.try_to_ir_cast().is_some()
    }

    /// Returns the IR [`IrUnOpType`], if this is a unary, non-casting opcode.
    pub fn try_to_ir_unop(&self) -> Option<IrUnOpType> {
        use ExpressionOpcode::*;
        match self {
            INT_NEGATE => Some(IrUnOpType::IntNegate),
            INT_2COMP => Some(IrUnOpType::Int2Comp),
            BOOL_NEGATE => Some(IrUnOpType::BoolNegate),
            FLOAT_NEG => Some(IrUnOpType::FloatNegate),
            FLOAT_ABS => Some(IrUnOpType::FloatAbs),
            FLOAT_SQRT => Some(IrUnOpType::FloatSqrt),
            FLOAT_CEIL => Some(IrUnOpType::FloatCeil),
            FLOAT_FLOOR => Some(IrUnOpType::FloatFloor),
            FLOAT_ROUND => Some(IrUnOpType::FloatRound),
            FLOAT_NAN => Some(IrUnOpType::FloatNaN),
            _ => None,
        }
    }

    /// Returns the IR [`IrBinOpType`], if this is a binary opcode.
    pub fn try_to_ir_biop(&self) -> Option<IrBinOpType> {
        use ExpressionOpcode::*;
        match self {
            PIECE => Some(IrBinOpType::Piece),
            INT_EQUAL => Some(IrBinOpType::IntEqual),
            INT_NOTEQUAL => Some(IrBinOpType::IntNotEqual),
            INT_LESS => Some(IrBinOpType::IntLess),
            INT_SLESS => Some(IrBinOpType::IntSLess),
            INT_LESSEQUAL => Some(IrBinOpType::IntLessEqual),
            INT_SLESSEQUAL => Some(IrBinOpType::IntSLessEqual),
            INT_ADD => Some(IrBinOpType::IntAdd),
            INT_SUB => Some(IrBinOpType::IntSub),
            INT_CARRY => Some(IrBinOpType::IntCarry),
            INT_SCARRY => Some(IrBinOpType::IntSCarry),
            INT_SBORROW => Some(IrBinOpType::IntSBorrow),
            INT_XOR => Some(IrBinOpType::IntXOr),
            INT_AND => Some(IrBinOpType::IntAnd),
            INT_OR => Some(IrBinOpType::IntOr),
            INT_LEFT => Some(IrBinOpType::IntLeft),
            INT_RIGHT => Some(IrBinOpType::IntRight),
            INT_SRIGHT => Some(IrBinOpType::IntSRight),
            INT_MULT => Some(IrBinOpType::IntMult),
            INT_DIV => Some(IrBinOpType::IntDiv),
            INT_REM => Some(IrBinOpType::IntRem),
            INT_SDIV => Some(IrBinOpType::IntSDiv),
            INT_SREM => Some(IrBinOpType::IntSRem),
            BOOL_XOR => Some(IrBinOpType::BoolXOr),
            BOOL_AND => Some(IrBinOpType::BoolAnd),
            BOOL_OR => Some(IrBinOpType::BoolOr),
            FLOAT_EQUAL => Some(IrBinOpType::FloatEqual),
            FLOAT_NOTEQUAL => Some(IrBinOpType::FloatNotEqual),
            FLOAT_LESS => Some(IrBinOpType::FloatLess),
            FLOAT_LESSEQUAL => Some(IrBinOpType::FloatLessEqual),
            FLOAT_ADD => Some(IrBinOpType::FloatAdd),
            FLOAT_SUB => Some(IrBinOpType::FloatSub),
            FLOAT_MULT => Some(IrBinOpType::FloatMult),
            FLOAT_DIV => Some(IrBinOpType::FloatDiv),
            _ => None,
        }
    }

    /// Returns the IR [`IrCastOpType`], if this is a unary, casting opcode.
    pub fn try_to_ir_cast(&self) -> Option<IrCastOpType> {
        use ExpressionOpcode::*;
        match self {
            INT_ZEXT => Some(IrCastOpType::IntZExt),
            INT_SEXT => Some(IrCastOpType::IntSExt),
            INT2FLOAT => Some(IrCastOpType::Int2Float),
            FLOAT2FLOAT => Some(IrCastOpType::Float2Float),
            TRUNC => Some(IrCastOpType::Trunc),
            POPCOUNT => Some(IrCastOpType::PopCount),
            LZCOUNT => Some(IrCastOpType::LzCount),
            _ => None,
        }
    }
}

/// A jump type mnemonic.
#[allow(missing_docs)]
#[allow(clippy::upper_case_acronyms)]
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum JmpOpcode {
    BRANCH,
    CBRANCH,
    BRANCHIND,
    CALL,
    CALLIND,
    CALLOTHER,
    RETURN,
}

impl Display for JmpOpcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use JmpOpcode::*;
        match self {
            BRANCH => write!(f, "BRANCH"),
            CBRANCH => write!(f, "CBRANCH"),
            BRANCHIND => write!(f, "BRANCHIND"),
            CALL => write!(f, "CALL"),
            CALLIND => write!(f, "CALLIND"),
            CALLOTHER => write!(f, "CALLOTHER"),
            RETURN => write!(f, "RETURN"),
        }
    }
}
