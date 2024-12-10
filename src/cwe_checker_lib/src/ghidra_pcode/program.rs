use super::Block;
use super::Function;

use crate::intermediate_representation::{Sub as IrFunction, Term as IrTerm, Tid};

use std::collections::{BTreeMap, HashSet};
use std::fmt::{self, Display};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct Program {
    functions: Vec<Function>,
}

impl Program {
    /// Returns a reference to the functions of this program.
    pub fn functions(&self) -> &Vec<Function> {
        &self.functions
    }

    /// Returns an iterator over the blocks in this program.
    pub fn blocks(&self) -> impl Iterator<Item = &Block> {
        self.functions()
            .iter()
            .flat_map(|func| func.blocks().iter())
    }

    /// 1:1 translation of the functions in this program to IR function terms.
    pub fn to_ir_function_terms_map(&self) -> BTreeMap<Tid, IrTerm<IrFunction>> {
        let jump_targets: HashSet<Tid> = self
            .blocks()
            .flat_map(|block| block.collect_jmp_targets())
            .collect();

        let ret: BTreeMap<Tid, IrTerm<IrFunction>> = self
            .functions()
            .iter()
            .map(|function| {
                let ir_function_term = function.to_ir_function_term(&jump_targets);

                (ir_function_term.tid.clone(), ir_function_term)
            })
            .collect();

        assert_eq!(self.functions.len(), ret.len(), "Duplicate function TID.");

        ret
    }
}

impl Display for Program {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for func in self.functions() {
            writeln!(f, "{}", func.summary_string())?;
            for block in func.blocks() {
                writeln!(f, "  {}", block.summary_string())?;
                for insn in block.instructions() {
                    if !insn.is_nop() {
                        writeln!(
                            f,
                            "    {}",
                            insn.to_string().replace('\n', "\n    ").trim_end()
                        )?;
                    }
                }
                writeln!(f)?;
            }
        }

        Ok(())
    }
}
