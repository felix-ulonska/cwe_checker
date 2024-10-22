//! This module implements a check for CWE-676: Use of Potentially Dangerous
//! Function.
//!
//! Potentially dangerous functions like memcpy can lead to security issues like
//! buffer overflows. See <https://cwe.mitre.org/data/definitions/676.html> for
//! a detailed description.
//!
//! # How the Check Works
//!
//! Calls to dangerous functions are flagged. The list of functions that are
//! considered dangerous can be configured in config.json. The default list is
//! based on
//! <https://github.com/01org/safestringlib/wiki/SDL-List-of-Banned-Functions>.
//!
//! # False Positives
//!
//! None known.
//!
//! # False Negatives
//!
//! None known.
use super::prelude::*;

use crate::prelude::*;
use crate::{
    intermediate_representation::{ExternSymbol, Sub, Term, Tid},
    utils::symbol_utils::get_calls_to_symbols,
};

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};

cwe_module!("CWE676", "0.1", check_cwe);

/// struct containing dangerous symbols from config.json
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Config {
    symbols: Vec<String>,
}

/// For each subroutine and each found dangerous symbol, check for calls to the
/// corresponding symbol.
pub fn get_calls<'a>(
    functions: &'a BTreeMap<Tid, Term<Sub>>,
    dangerous_symbols: &'a HashMap<&'a Tid, &'a str>,
) -> Vec<(&'a str, &'a Tid, &'a str)> {
    let mut calls: Vec<(&str, &Tid, &str)> = Vec::new();

    for f in functions.values() {
        calls.append(&mut get_calls_to_symbols(f, dangerous_symbols));
    }

    calls
}

/// Generate cwe warnings for potentially dangerous function calls
pub fn generate_cwe_warnings<'a>(
    dangerous_calls: Vec<(&'a str, &'a Tid, &'a str)>,
) -> Vec<CweWarning> {
    let mut cwe_warnings: Vec<CweWarning> = Vec::new();
    for (sub_name, jmp_tid, target_name) in dangerous_calls.iter() {
        let address = jmp_tid.address();
        let description: String = format!(
            "(Use of Potentially Dangerous Function) {sub_name} ({address}) -> {target_name}"
        );
        let cwe_warning = CweWarning::new(
            String::from(CWE_MODULE.name),
            String::from(CWE_MODULE.version),
            description,
        )
        .addresses(vec![address.to_string()])
        .tids(vec![format!("{jmp_tid}")])
        .symbols(vec![String::from(*sub_name)])
        .other(vec![vec![
            String::from("dangerous_function"),
            String::from(*target_name),
        ]]);

        cwe_warnings.push(cwe_warning);
    }

    cwe_warnings
}

/// Filter external symbols by dangerous symbols
pub fn filter_dangerous_ext_symbols<'a>(
    external_symbols: &'a BTreeMap<Tid, ExternSymbol>,
    dangerous_symbols: &'a [String],
) -> HashMap<&'a Tid, &'a str> {
    let dangerous_symbols: HashSet<&'a String> = dangerous_symbols.iter().collect();
    external_symbols
        .iter()
        .filter_map(|(tid, symbol)| {
            dangerous_symbols
                .get(&symbol.name)
                .map(|name| (tid, name.as_str()))
        })
        .collect()
}

/// Iterate through all function calls inside the program and flag calls to
/// those functions that are marked as unsafe via the configuration file.
pub fn check_cwe(
    analysis_results: &AnalysisResults,
    cwe_params: &serde_json::Value,
    _debug_settings: &debug::Settings,
) -> WithLogs<Vec<CweWarning>> {
    let mut logs = Vec::new();

    let project = analysis_results.project;
    let config: Config = serde_json::from_value(cwe_params.clone()).unwrap();
    let prog = &project.program;
    let functions = &prog.term.subs;
    let external_symbols = &prog.term.extern_symbols;

    let dangerous_ext_symbols = filter_dangerous_ext_symbols(external_symbols, &config.symbols);
    let mut msg = format!(
        "{}: Program imports the following dangerous symbols: ",
        CWE_MODULE.name
    );
    for (fn_tid, fn_name) in dangerous_ext_symbols.iter() {
        msg.push_str(&format!("{}({}),", fn_tid, fn_name));
    }
    logs.push(LogMessage::new_info(msg));

    let dangerous_ext_calls = get_calls(functions, &dangerous_ext_symbols);

    WithLogs::new(
        generate_cwe_warnings(dangerous_ext_calls)
            .deduplicate_first_address()
            .move_logs_to(&mut logs)
            .into_object(),
        logs,
    )
}
