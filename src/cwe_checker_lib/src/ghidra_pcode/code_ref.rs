use std::fmt::{self, Display};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct CodeRef {
    pub from: i64,
    pub to: i64,
}

impl Display for CodeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CODEREF: {:#x} -> {:#x}", self.from, self.to)
    }
}

