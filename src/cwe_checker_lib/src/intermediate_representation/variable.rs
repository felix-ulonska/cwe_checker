use super::ByteSize;
use crate::prelude::*;
use std::fmt::Display;

/// A variable represents a register with a known size and name.
///
/// Variables can be physical or virtual:
///
/// - Physical variables correspond to CPU registers and are thus read/write
///   able by callee and caller functions. In this sense they are akin to global
///   variables in source languages.
/// - Virtual registers are only used to store intermediate results necessary
///   for representing more complex assembly instructions. In principle they are
///   only valid until the end of the current assembly instruction. However, one
///   assembly instruction may span more than one basic block in the
///   intermediate representation (but never more than one function). In this
///   sense they are akin to local variables.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct Variable {
    /// The name of the variable. Equals the register name if the variable is a
    /// physical register.
    pub name: String,
    /// The size (in bytes) of the variable.
    pub size: ByteSize,
    /// Set to `false` for physical registers and to `true` for temporary
    /// (virtual) variables.
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
    /// Prefix of variable names that correspond to unnamed subregisters.
    pub const UNNAMED_SUBREG_PREFIX: &'static str = "$R_";
    /// Prefix of variable names that correspond to temporary registers.
    pub const TMP_REG_PREFIX: &'static str = "$U_";

    /// Returns true iff the variable is physical.
    pub fn is_physical_register(&self) -> bool {
        !self.is_temp
    }

    /// Returns true iff the variable corresponds to a subregister of a
    /// physical register.
    ///
    /// (Such variables do not appear in the final IR, only during the
    /// translation process.)
    pub fn is_unnamed_subregister(&self) -> bool {
        self.name.starts_with(Self::UNNAMED_SUBREG_PREFIX)
    }

    /// Extracts the offset into the register address space.
    ///
    /// (Only useful during IR generation.)
    pub fn name_to_offset(&self) -> Option<u64> {
        if self.is_unnamed_subregister() || !self.is_physical_register() {
            let offset = self.name.split('_').last().unwrap().to_string();

            Some(u64::from_str_radix(offset.strip_prefix("0x").unwrap(), 16).unwrap())
        } else {
            None
        }
    }
}
