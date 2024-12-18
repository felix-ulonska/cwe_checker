use core::fmt;
use std::fmt::Display;

use serde::{Deserialize, Deserializer, Serialize};

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
    name: String,
    base_address: String,
    #[serde(deserialize_with = "deserialize_hex")]
    data: Vec<u8>,
    size: i32,
}

impl Display for MemoryBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MEM_SEGMENT: {} @ {} size {}", self.name, self.base_address, self.size)
    }
}
