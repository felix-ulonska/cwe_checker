//! The implemented CWE checks.
//!
//! See their module descriptions for detailed information about each check.
//!
//! Currently the **Memory** check is not contained in this module
//! but directly incorporated into the
//! [`pointer_inference`](crate::analysis::pointer_inference) module.
//! See there for detailed information about this check.

/// Checkers that are supported for Linux kernel modules.
pub const MODULES_LKM: [&str; 10] = [
    "CWE134", "CWE190", "CWE215", "CWE252", "CWE416", "CWE457", "CWE467", "CWE476", "CWE676",
    "CWE789",
];

pub mod cwe_119;
pub mod cwe_134;
pub mod cwe_190;
pub mod cwe_215;
pub mod cwe_243;
pub mod cwe_252;
pub mod cwe_332;
pub mod cwe_337;
pub mod cwe_367;
pub mod cwe_416;
pub mod cwe_426;
pub mod cwe_467;
pub mod cwe_476;
pub mod cwe_560;
pub mod cwe_676;
pub mod cwe_78;
pub mod cwe_782;
pub mod cwe_789;

pub mod prelude {
    //! Prelude imports for CWE checkers.
    pub use super::{cwe_module, CweModule, CweModuleFn};
    pub use crate::utils::debug;
    pub use crate::utils::log::{CweWarning, DeduplicateCweWarnings, LogMessage, WithLogs};
}
use prelude::*;

use crate::pipeline::AnalysisResults;

/// The generic function signature for the main function of a CWE module
pub type CweModuleFn =
    fn(&AnalysisResults, &serde_json::Value, &debug::Settings) -> WithLogs<Vec<CweWarning>>;

/// A structure containing general information about a CWE analysis module,
/// including the function to be called to run the analysis.
pub struct CweModule {
    /// The name of the CWE check.
    pub name: &'static str,
    /// The version number of the CWE check.
    /// Should be incremented whenever significant changes are made to the check.
    pub version: &'static str,
    /// The function that executes the check and returns CWE warnings found during the check.
    pub run: CweModuleFn,
}

#[macro_export]
/// Defines a CWE checker module.
macro_rules! cwe_module {
    (
        $name:literal, $version:literal, $run:ident,
        config: $($(#[doc = $config_doc:expr])*$config_key:ident: $config_type:ty),
        *$(,)?
     ) => {
        cwe_module!($name, $version, $run);
        #[doc = "The checker-specific configuration."]
        #[derive(serde::Serialize, serde::Deserialize)]
        struct Config {
            $(
                $(
                    #[doc = $config_doc]
                )*
                $config_key: $config_type,
            )*
        }
    };
    ($name:literal, $version:literal, $run:ident$(,)?) => {
        #[doc = "The checker's name, version, and entry point."]
        pub static CWE_MODULE: $crate::checkers::prelude::CweModule =
            $crate::checkers::prelude::CweModule {
                name: $name,
                version: $version,
                run: $run,
            };
    }
}
pub use cwe_module;

impl std::fmt::Display for CweModule {
    /// Print the module name and its version number.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, r#""{}": "{}""#, self.name, self.version)
    }
}

/// Get a list of all known analysis modules.
pub fn get_modules() -> Vec<&'static CweModule> {
    vec![
        &crate::checkers::cwe_78::CWE_MODULE,
        &crate::checkers::cwe_119::CWE_MODULE,
        &crate::checkers::cwe_134::CWE_MODULE,
        &crate::checkers::cwe_190::CWE_MODULE,
        &crate::checkers::cwe_215::CWE_MODULE,
        &crate::checkers::cwe_243::CWE_MODULE,
        &crate::checkers::cwe_252::CWE_MODULE,
        &crate::checkers::cwe_332::CWE_MODULE,
        &crate::checkers::cwe_337::CWE_MODULE,
        &crate::checkers::cwe_367::CWE_MODULE,
        &crate::checkers::cwe_416::CWE_MODULE,
        &crate::checkers::cwe_426::CWE_MODULE,
        &crate::checkers::cwe_467::CWE_MODULE,
        &crate::checkers::cwe_476::CWE_MODULE,
        &crate::checkers::cwe_560::CWE_MODULE,
        &crate::checkers::cwe_676::CWE_MODULE,
        &crate::checkers::cwe_782::CWE_MODULE,
        &crate::checkers::cwe_789::CWE_MODULE,
        &crate::analysis::pointer_inference::CWE_MODULE,
    ]
}
