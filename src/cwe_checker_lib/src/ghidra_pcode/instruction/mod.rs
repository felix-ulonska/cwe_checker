//! Assembly instructions.

use super::Term;

use crate::intermediate_representation::Tid;

use serde::{Deserialize, Serialize};

use std::collections::HashSet;
use std::fmt::{self, Display};

/// An assembly instruction.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Instruction {
    /// Instruction mnemonic.
    mnemonic: String,
    /// Address at which the first instruction byte is located.
    address: String,
    /// Number of bytes that belong to this instruction.
    size: u64,
    /// Pcode terms that this instruction decomposes into.
    terms: Vec<Term>,
    /// Potential targets of an indirect control flow transfer.
    potential_targets: Option<Vec<String>>,
    /// Fall-through target.
    fall_through: Option<String>,
}

impl Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for term in &self.terms {
            writeln!(f, "{}", term)?;
        }

        Ok(())
    }
}

impl Instruction {
    /// Returns the address of the first byte that belongs to this instruction.
    pub fn address(&self) -> &String {
        &self.address
    }

    /// Returns the mnemonic of this instruction.
    pub fn mnemonic(&self) -> &String {
        &self.mnemonic
    }

    /// Returns true iff this is a NOOP.
    pub fn is_nop(&self) -> bool {
        self.terms.is_empty()
    }

    /// Returns the Pcode terms that this instruction decomposes into.
    pub fn terms(&self) -> &Vec<Term> {
        &self.terms
    }

    /// Returns potential targets of an indirect control flow transfer.
    pub fn potential_targets(&self) -> Option<&Vec<String>> {
        self.potential_targets.as_ref()
    }

    /// Returns the fall-through target of this instruction.
    pub fn fall_through(&self) -> Option<&String> {
        self.fall_through.as_ref()
    }

    /// Collects all jump targets of an instruction and returns their [`Tid`].
    ///
    /// The id follows the naming convention `blk_<address>`. If the target is
    /// within a pcode sequence and the index is larger 0, `_<pcode_index>` is
    /// suffixed.
    pub fn collect_jmp_and_fall_through_targets(
        &self,
        _consecutive_instr: Option<&Instruction>,
    ) -> HashSet<Tid> {
        let mut jump_targets = HashSet::new();

        for jmp_term in self.terms().iter().filter(|term| term.is_jump()) {
            let targets = jmp_term.collect_jmp_targets(self);
            jump_targets.extend(targets);

            if let Some(fall_through) = jmp_term.get_fall_through_target(self) {
                jump_targets.insert(fall_through);
            }
        }

        jump_targets
    }

    /// Returns true iff this instruction contains a term with the given index.
    pub fn contains_term_index(&self, index: u64) -> bool {
        index < (self.terms().len() as u64)
    }

    /// Returns true iff this instruction is in a MIPS jump delay slot.
    pub fn is_mips_jump_delay_slot(&self) -> bool {
        self.mnemonic().starts_with("_")
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    impl Instruction {
        /// Returns `InstructionSimple`, with mnemonic `mock`, size `1`, `potential_targets` and `fall_through` set to `None`.
        pub fn mock<'a, T>(address: &'a str, pcode_ops: T) -> Self
        where
            T: IntoIterator,
            T::Item: Into<&'a str>,
        {
            let mut ops = Vec::new();
            for (index, op) in pcode_ops.into_iter().enumerate() {
                ops.push(PcodeOperation::mock(op.into()).with_index(index as u64));
            }
            Instruction {
                mnemonic: "mock".into(),
                address: address.to_string(),
                size: 1,
                terms: ops,
                potential_targets: None,
                fall_through: None,
            }
        }
    }

    #[test]
    fn test_instruction_get_u64_address() {
        let mut instr = Instruction {
            mnemonic: "nop".into(),
            address: "0x00123ABFF".into(),
            size: 2,
            terms: vec![],
            potential_targets: None,
            fall_through: None,
        };
        assert_eq!(instr.get_u64_address(), 0x123ABFF);
        instr.address = "0x123ABFF".into();
        assert_eq!(instr.get_u64_address(), 0x123ABFF);
    }

    #[test]
    #[should_panic]
    fn test_instruction_get_u64_address_not_hex() {
        Instruction::mock("0xABG".into(), Vec::<&str>::new()).get_u64_address();
    }
}
