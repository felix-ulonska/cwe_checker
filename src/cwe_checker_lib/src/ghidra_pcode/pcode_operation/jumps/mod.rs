//! Pcode jump operations.

use super::PcodeOperation;

use crate::{
    ghidra_pcode::{pcode_opcode::PcodeOpcode, JmpOpcode},
    intermediate_representation::{Jmp as IrJmp, Tid},
};

impl PcodeOperation {
    /// Helper function to unwrap the jump opcode of a Pcode operation.
    ///
    /// Panics if `self` is not a jump.
    pub fn unwrap_jmp_opcode(&self) -> &JmpOpcode {
        if let PcodeOpcode::Jump(jmp_type) = &self.opcode() {
            jmp_type
        } else {
            panic!("Jump type expected.")
        }
    }

    /// Returns true iff this is a jump operation.
    pub fn is_jump(&self) -> bool {
        matches!(self.pcode_mnemonic, PcodeOpcode::Jump(_))
    }

    /// Returns true iff this is a direct jump operation.
    pub fn is_direct_jump(&self) -> bool {
        matches!(
            self.pcode_mnemonic,
            PcodeOpcode::Jump(JmpOpcode::BRANCH)
                | PcodeOpcode::Jump(JmpOpcode::CBRANCH)
                | PcodeOpcode::Jump(JmpOpcode::CALL)
        )
    }

    /// Create a branch instruction.
    pub fn to_ir_jmp_branch(&self, target: Tid) -> IrJmp {
        IrJmp::Branch(target)
    }

    /// Create a conditional branch.
    pub fn to_ir_jmp_cbranch(&self, target: Tid) -> IrJmp {
        IrJmp::CBranch {
            target,
            condition: self.input1().unwrap().to_ir_expr(),
        }
    }

    /// Create an indirect branch.
    pub fn to_ir_jmp_branch_ind(&self) -> IrJmp {
        IrJmp::BranchInd(self.input0().unwrap().to_ir_expr())
    }

    /// Create a call.
    pub fn to_ir_jmp_call(&self, return_target: Option<Tid>) -> IrJmp {
        IrJmp::Call {
            target: Tid::new_function(self.input0().unwrap().get_ram_address_as_string().unwrap()),
            return_: return_target,
        }
    }

    /// Create an indirect call.
    pub fn to_ir_jmp_call_ind(&self, return_target: Option<Tid>) -> IrJmp {
        IrJmp::CallInd {
            target: self.input0().unwrap().to_ir_expr(),
            return_: return_target,
        }
    }

    /// Create a `CallOther` instruction.
    ///
    /// The description is given by the mnemonic of the corresponding assembly
    /// instruction
    pub fn to_ir_jmp_call_other(&self, return_target: Option<Tid>, description: &str) -> IrJmp {
        // FIXME: The description shown by Ghidra is actually not the mnemonic!
        // But it is unclear how one can access the description through Ghidras
        // API. Furthermore, we do not encode the optional input varnodes that
        // Ghidra allows for CALLOTHER operations.
        IrJmp::CallOther {
            description: description.to_string(),
            return_: return_target,
        }
    }

    /// Create a return instruction.
    pub fn to_ir_jmp_return(&self) -> IrJmp {
        IrJmp::Return(self.input0().unwrap().to_ir_expr())
    }
}

#[cfg(test)]
mod tests;
