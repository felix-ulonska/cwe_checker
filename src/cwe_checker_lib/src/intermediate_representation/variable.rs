use super::ByteSize;
use crate::prelude::*;
use std::fmt::Display;

/// A variable represents a register with a known size and name.
///
/// Variables can be temporary (or virtual).
/// In this case they do not represent actual physical registers
/// and are only used to store intermediate results necessary for representing more complex assembly instructions.
/// Temporary variables are only valid until the end of the current assembly instruction.
/// However, one assembly instruction may span more than one basic block in the intermediate representation
/// (but never more than one function).
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct Variable {
    /// The name of the variable. Equals the register name if the variable is a physical register.
    pub name: String,
    /// The size (in bytes) of the variable.
    pub size: ByteSize,
    /// Set to `false` for physical registers and to `true` for temporary (virtual) variables.
    pub is_temp: bool,
}

impl Display for Variable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.name, self.size)?;
        if self.is_temp {
            write!(f, "(temp)")?;
        }
        Ok(())
    }
}

impl Variable {
    pub fn is_physical_register(&self) -> bool {
        !self.is_temp
    }

    pub fn is_unnamed_subregister(&self) -> bool {
        self.name.starts_with("$R_")
    }

    pub fn name_to_offset(&self) -> Option<u64> {
        if self.is_unnamed_subregister() || !self.is_physical_register() {
            let offset = self.name.split('_').last().unwrap().to_string();

            Some(u64::from_str_radix(offset.strip_prefix("0x").unwrap(), 16).unwrap())
        } else {
            None
        }
    }
}
