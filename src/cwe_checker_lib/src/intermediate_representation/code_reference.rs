use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct CodeReference {
    pub from: i64,
    pub to: i64,
}
