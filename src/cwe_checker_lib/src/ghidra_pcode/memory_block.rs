use core::fmt;
use std::fmt::Display;

use serde::{Deserialize, Deserializer, Serialize};

use crate::utils::binary::MemorySegment;

pub fn deserialize_hex<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;

    let bytes = s
        .split_whitespace()
        .map(|hex| u8::from_str_radix(hex, 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(serde::de::Error::custom)?;

    Ok(bytes)
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct MemoryBlock {
    pub name: String,
    pub base_address: u64,
    #[serde(deserialize_with = "deserialize_hex")]
    pub data: Vec<u8>,
    pub size: i32,
    pub is_executable: bool,
    pub is_readable: bool,
    pub is_writeable: bool
}

fn display_prem(perm: bool, display_char: &str) -> &str {
    if perm {
        display_char
    } else {
        "-"
    }
}

impl MemoryBlock {
    pub fn to_ir_memory_segment(&self) -> MemorySegment {
        MemorySegment {
            name : Some(self.name.to_owned()),
            bytes : self.data.clone(),
            base_address : self.base_address,
            read_flag : self.is_readable,
            execute_flag : self.is_executable,
            write_flag : self.is_writeable
        }
    }
}

impl Display for MemoryBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MEM_SEGMENT: {} @ {:#x} size {:#x} [{}{}{}]",
            self.name,
            self.base_address,
            self.size,
            display_prem(self.is_readable, "R"),
            display_prem(self.is_writeable, "W"),
            display_prem(self.is_executable, "X")
        )
    }
}
