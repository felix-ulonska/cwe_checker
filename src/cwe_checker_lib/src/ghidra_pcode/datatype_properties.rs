//! C data type properties.

use crate::intermediate_representation::DatatypeProperties as IrDatatypeProperties;

use std::convert::From;

use serde::{Deserialize, Serialize};

/// C data type properties for a given platform.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct DatatypeProperties {
    char_size: u64,
    double_size: u64,
    float_size: u64,
    integer_size: u64,
    long_double_size: u64,
    long_long_size: u64,
    long_size: u64,
    pointer_size: u64,
    short_size: u64,
}

impl From<DatatypeProperties> for IrDatatypeProperties {
    fn from(datatype_properties: DatatypeProperties) -> Self {
        Self {
            char_size: datatype_properties.char_size.into(),
            double_size: datatype_properties.double_size.into(),
            float_size: datatype_properties.float_size.into(),
            integer_size: datatype_properties.integer_size.into(),
            long_double_size: datatype_properties.long_double_size.into(),
            long_long_size: datatype_properties.long_long_size.into(),
            long_size: datatype_properties.long_size.into(),
            pointer_size: datatype_properties.pointer_size.into(),
            short_size: datatype_properties.short_size.into(),
        }
    }
}
