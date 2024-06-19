use crate::prelude::*;

mod builder_high_lvl;
mod builder_low_lvl;

/// A term identifier consisting of an ID string (which is required to be unique)
/// and an address to indicate where the term is located.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, PartialOrd, Ord)]
pub struct Tid {
    /// The unique ID of the term.
    pub id: String,
    /// The address where the term is located.
    pub address: String,
}

impl Tid {
    /// Prefix for IDs of artificial sinks in the control flow graph.
    ///
    /// Dummy blocks with such TIDs are added for different purposes, e.g., as
    /// targets for jumps to non-existing targets or return targets for calls to
    /// non-returning functions.
    const ARTIFICIAL_SINK_BLOCK_ID_PREFIX: &'static str = "Artificial Sink Block";
    /// The ID of the artificial sink sub.
    ///
    /// This is used as the target for calls to non-existing functions.
    const ARTIFICIAL_SINK_SUB_ID: &'static str = "Artificial Sink Sub";
    /// Address for use in IDs of terms that do not have an address.
    const UNKNOWN_ADDRESS: &'static str = "UNKNOWN";

    /// Generate a new term identifier with the given ID string
    /// and with unknown address.
    pub fn new<T: ToString>(val: T) -> Tid {
        Tid {
            id: val.to_string(),
            address: Self::UNKNOWN_ADDRESS.to_string(),
        }
    }

    /// Generate a new term identifier for an instruction with `index` at
    /// `address`.
    pub fn new_instr<T: Display + ?Sized>(address: &T, index: u64) -> Self {
        Tid::new_instr_with_suffix::<_, &str>(address, index, None)
    }

    /// Converts TID into a TID for an instruction at the same address.
    pub fn into_instr(self) -> Self {
        Self {
            id: format!("instr_{}_0", self.address),
            address: self.address,
        }
    }

    pub fn new_instr_with_suffix<T, U>(address: &T, index: u64, suffix: Option<&U>) -> Self
    where
        T: Display + ?Sized,
        U: Display + ?Sized,
    {
        match suffix {
            Some(suffix) => Self {
                id: format!("instr_{}_{}_{}", address, index, suffix),
                address: address.to_string(),
            },
            None => Self {
                id: format!("instr_{}_{}", address, index),
                address: address.to_string(),
            },
        }
    }

    /// Generate a new term identifier for a block with `index` at `address`.
    pub fn new_block<T: Display + ?Sized>(address: &T, index: u64) -> Self {
        let id = match index {
            0 => format!("blk_{}", address),
            _ => format!("blk_{}_{}", address, index),
        };

        Self {
            id,
            address: address.to_string(),
        }
    }

    /// Returns true iff this is a TID for a block.
    pub fn is_block(&self) -> bool {
        self.id.starts_with("blk_")
    }

    /// Returns the TID for a function at the given address.
    pub fn new_function<T: Display + ?Sized>(address: &T) -> Self {
        Self {
            id: format!("FUN_{}", address),
            address: address.to_string(),
        }
    }

    /// Add a suffix to the ID string and return the new `Tid`
    pub fn with_id_suffix(self, suffix: &str) -> Self {
        Tid {
            id: self.id + suffix,
            address: self.address,
        }
    }

    /// Returns true if the ID string ends with the provided suffix.
    pub fn has_id_suffix(&self, suffix: &str) -> bool {
        self.id.ends_with(suffix)
    }

    /// Generate the ID of a block starting at the given address.
    ///
    /// Note that the block may not actually exist.
    /// For cases where one assembly instruction generates more than one block,
    /// the returned block ID is the one that would be executed first if a jump to the given address happened.
    pub fn blk_id_at_address(address: &str) -> Tid {
        Tid {
            id: format!("blk_{address}"),
            address: address.to_string(),
        }
    }

    /// Returns a new ID for an artificial sink block with the given suffix.
    pub fn artificial_sink_block<T: Display>(suffix: T) -> Self {
        Self {
            id: format!("{}{}", Self::ARTIFICIAL_SINK_BLOCK_ID_PREFIX, suffix),
            address: Self::UNKNOWN_ADDRESS.to_string(),
        }
    }

    /// Returns a new ID for the artificial sink block of the given funtion.
    pub fn artificial_sink_block_for_fn(fn_tid: &Tid) -> Self {
        Self {
            id: format!("{}_{}", Self::ARTIFICIAL_SINK_BLOCK_ID_PREFIX, fn_tid),
            address: Self::UNKNOWN_ADDRESS.to_string(),
        }
    }

    /// Returns a new ID for the artificial sink sub.
    pub fn artificial_sink_sub() -> Self {
        Self {
            id: Self::ARTIFICIAL_SINK_SUB_ID.to_string(),
            address: Self::UNKNOWN_ADDRESS.to_string(),
        }
    }

    /// Returns true iff the ID is for the artificial sink block with the given
    /// suffix.
    pub fn is_artificial_sink_block(&self, suffix: &str) -> bool {
        self.id.starts_with(Self::ARTIFICIAL_SINK_BLOCK_ID_PREFIX)
            && self.has_id_suffix(suffix)
            && self.address == Self::UNKNOWN_ADDRESS
    }

    /// Returns true iff the ID is for the artificial sink sub.
    pub fn is_artificial_sink_sub(&self) -> bool {
        self.id == Self::ARTIFICIAL_SINK_SUB_ID && self.address == Self::UNKNOWN_ADDRESS
    }

    /// Returns the address of this TID.
    pub fn address(&self) -> &String {
        &self.address
    }
}

impl std::fmt::Display for Tid {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "{}", self.id)
    }
}

/// A term is an object inside a binary with an address and an unique ID (both contained in the `tid`).
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Term<T> {
    /// The term identifier, which also contains the address of the term
    pub tid: Tid,
    /// The object
    pub term: T,
}

#[cfg(test)]
pub mod tests {
    use super::*;

    impl Tid {
        /// Mock a TID with the given name and the address parsed from the name.
        /// The name must have the form `prefix_address[_suffix]`, e.g. `instr_0x00001234_5`.
        pub fn mock(tid: &str) -> Tid {
            let components: Vec<_> = tid.split("_").collect();
            Tid {
                id: tid.to_string(),
                address: components[1].to_string(),
            }
        }
    }
}
