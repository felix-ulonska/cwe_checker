//! This module contains various utility modules and helper functions.

pub mod arguments;
pub mod binary;
pub mod debug;
pub mod ghidra;
pub mod graph_utils;
pub mod log;
pub mod symbol_utils;

use crate::prelude::*;

use std::{env, fs, path};

use anyhow::bail;

const ENV_CWE_CHECKER_CONFIGS_PATH: &str = "CWE_CHECKER_CONFIGS_PATH";
const ENV_CWE_CHECKER_GHIDRA_PLUGINS_PATH: &str = "CWE_CHECKER_GHIDRA_PLUGINS_PATH";

/// Get the contents of a configuration file.
///
/// We first search the file in our config directory. Then, we fall back to
/// the CWE_CHECKER_CONFIG environment variable.
pub fn read_config_file(filename: &str) -> Result<serde_json::Value, Error> {
    let config_path = if let Some(config_path) = get_config_path_from_project_dir(filename) {
        config_path
    } else if let Some(config_path) = get_path_from_env(ENV_CWE_CHECKER_CONFIGS_PATH, filename) {
        config_path
    } else {
        bail!("Unable to find configuration file: {}.", filename)
    };
    let config_file = fs::read_to_string(config_path)
        .context(format!("Could not read configuration file: {}", filename))?;
    Ok(serde_json::from_str(&config_file)?)
}

fn get_config_path_from_project_dir(filename: &str) -> Option<path::PathBuf> {
    let project_dirs = directories::ProjectDirs::from("", "", "cwe_checker")?;
    let config_dir = project_dirs.config_dir();
    let config_path = config_dir.join(filename);

    if config_path.exists() {
        Some(config_path)
    } else {
        None
    }
}

/// Get the path to a Ghidra plugin that is bundled with the cwe_checker.
///
/// We first search the plugin in our data directory, then we fall back to
/// the CWE_CHECKER_GHIDRA_PLUGIN_PATH environment variable.
pub fn get_ghidra_plugin_path(plugin_name: &str) -> Result<path::PathBuf, Error> {
    if let Some(ghidra_plugin_path) = get_ghidra_plugin_path_from_project_dirs(plugin_name) {
        Ok(ghidra_plugin_path)
    } else if let Some(ghidra_plugin_path) =
        get_path_from_env(ENV_CWE_CHECKER_GHIDRA_PLUGINS_PATH, plugin_name)
    {
        Ok(ghidra_plugin_path)
    } else {
        bail!("Unable to find Ghidra plugin: {}", plugin_name)
    }
}

fn get_ghidra_plugin_path_from_project_dirs(plugin_name: &str) -> Option<path::PathBuf> {
    let project_dirs = directories::ProjectDirs::from("", "", "cwe_checker")?;
    let data_dir = project_dirs.data_dir();
    let plugin_path = data_dir.join("ghidra").join(plugin_name);

    if plugin_path.exists() {
        Some(plugin_path)
    } else {
        None
    }
}

fn get_path_from_env(var: &str, filename: &str) -> Option<path::PathBuf> {
    let val = env::var(var).ok()?;
    let path = path::PathBuf::from(val).join(filename);

    if path.exists() {
        Some(path)
    } else {
        None
    }
}
