use super::Block;

use crate::intermediate_representation::{Sub as IrFunction, Term as IrTerm, Tid};

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

pub mod extern_function;
pub use extern_function::ExternFunction;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Function {
    name: String,
    address: String,
    blocks: Vec<Block>,
}

impl Function {
    /// Returns a one-line signature of this funtion.
    pub fn summary_string(&self) -> String {
        format!("FUNCTION: {} @ {}", self.name, self.address)
    }

    /// Returns a reference to the basic block of this funtion.
    pub fn blocks(&self) -> &Vec<Block> {
        &self.blocks
    }

    /// 1:1 translation of this function to an IR funtion term.
    pub fn to_ir_function_term(&self, jump_targets: &HashSet<Tid>) -> IrTerm<IrFunction> {
        let ir_function_term = IrFunction::new::<_, &str>(
            &self.name,
            self.blocks()
                .iter()
                .flat_map(|block| block.to_ir_blocks(jump_targets).into_iter())
                .collect(),
            None,
        );

        IrTerm::new(Tid::new_function(&self.address), ir_function_term)
    }
}
