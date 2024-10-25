//! This module implements a check for CWE-243: Creation of chroot Jail Without
//! Changing Working Directory.
//!
//! Creating a chroot Jail without changing the working directory afterwards
//! does not prevent access to files outside of the jail.
//!
//! See <https://cwe.mitre.org/data/definitions/243.html> for detailed a
//! description.
//!
//! ## How the check works
//!
//! According to <http://www.unixwiz.net/techtips/chroot-practices.html>, there
//! are several ways to achieve the safe creation of a chroot jail.
//! One can either call chdir after chroot or, if chdir is called before chroot,
//! drop priviledges after the chroot call. The functions used to drop
//! priviledges are configurable in config.json. We check whether each function
//! that calls chroot is using one of these safe call sequences to create the
//! chroot jail. If not, a warning is emitted.
//!
//! ## False Positives
//!
//! None known.
//!
//! ## False Negatives
//!
//! We do not check whether the parameters to chdir, chroot and the priviledge
//! dropping functions are suitable to create a safe chroot jail.
use super::prelude::*;

use crate::analysis::graph::intraprocedural_cfg::IntraproceduralCfg;
use crate::analysis::graph::Node;
use crate::intermediate_representation::*;
use crate::prelude::*;
use crate::utils::graph_utils::is_sink_call_reachable_from_source_call;
use crate::utils::symbol_utils::find_symbol;

cwe_module!(
    "CWE243",
    "0.2",
    check_cwe,
    config:
        /// This configuration contains a list of functions that are assumed to
        /// be used to correctly drop priviledges after a `chroot` call.
        priviledge_dropping_functions: Vec<String>,
);

/// Check whether the given block calls the given TID.
///
/// If yes, return the TID of the jump term that contains the call.
fn blk_calls_tid(blk: &Term<Blk>, tid: &Tid) -> Option<Tid> {
    let call_targets = blk.get_call_targets()?;

    call_targets.iter().find_map(|t| {
        if *t == tid {
            Some(blk.jmps().next().unwrap().tid.clone())
        } else {
            None
        }
    })
}

/// Check whether the function `f` calls both the `chdir_tid`
/// and at least one of the `priviledge_dropping_tids`.
///
/// If yes, return true.
fn f_calls_chdir_and_priviledge_dropping_func(
    p: &Program,
    f: &Term<Sub>,
    chdir_tid: &Tid,
    priviledge_dropping_tids: &[Tid],
) -> bool {
    let cfg = IntraproceduralCfg::new(p, f);
    let callees = cfg.callees();

    callees.keys().any(|callee_tid| *callee_tid == chdir_tid)
        && callees
            .keys()
            .any(|callee_tid| priviledge_dropping_tids.contains(callee_tid))
}

/// Generate a CWE warning for a CWE hit.
fn generate_cwe_warning(sub: &Term<Sub>, callsite: &Tid) -> CweWarning {
    CweWarning::new(
        CWE_MODULE.name,
        CWE_MODULE.version,
        format!(
            "(The program utilizes chroot without dropping privileges and/or changing the directory) at {} ({})",
            callsite.address(), sub.term.name
        ))
        .tids(vec![format!("{callsite}")])
        .addresses(vec![callsite.address().to_string()])
        .symbols(vec![sub.term.name.clone()])
}

/// Run the check.
///
/// For each call to `chroot` we check
/// - that it is either followed by a call to `chdir` in the same function
/// - or that the same function contains calls to `chdir`
///   and a call to a function that can be used to drop priviledges.
///
/// If both are false, we assume that the chroot-jail is insecure and report a
/// CWE hit.
pub fn check_cwe(
    analysis_results: &AnalysisResults,
    cwe_params: &serde_json::Value,
    _debug_settings: &debug::Settings,
) -> WithLogs<Vec<CweWarning>> {
    let mut cwe_warnings = Vec::new();
    let project = &analysis_results.project;
    let program = &analysis_results.project.program;
    let graph = &analysis_results.control_flow_graph;

    let config: Config = serde_json::from_value(cwe_params.clone()).unwrap();
    let priviledge_dropping_tids: Vec<Tid> = config
        .priviledge_dropping_functions
        .into_iter()
        .filter_map(|func_name| {
            if let Some((tid, _)) = find_symbol(&project.program, &func_name) {
                Some(tid.clone())
            } else {
                None
            }
        })
        .collect();

    let chroot_tid = match find_symbol(&project.program, "chroot") {
        Some((tid, _)) => tid.clone(),
        // `chroot` is not called by the program.
        None => return WithLogs::wrap(Vec::new()),
    };
    let chdir_tid_op = find_symbol(&project.program, "chdir").map(|(tid, _)| tid.clone());

    for node in graph.node_indices() {
        let Node::BlkEnd(blk, sub) = graph[node] else {
            continue;
        };
        let Some(callsite_tid) = blk_calls_tid(blk, &chroot_tid) else {
            // No call to `chroot`.
            continue;
        };
        let Some(chdir_tid) = &chdir_tid_op else {
            // There is no `chdir` symbol, so the chroot jail cannot be
            // secured.
            cwe_warnings.push(generate_cwe_warning(sub, &callsite_tid));
            continue;
        };
        let chroot_return_to_node = graph.neighbors(node).next().unwrap();
        // If chdir is called after chroot, we assume a secure chroot jail.
        if is_sink_call_reachable_from_source_call(
            graph,
            chroot_return_to_node,
            &chroot_tid,
            chdir_tid,
        )
        .is_none()
        {
            // If chdir is not called after chroot, it has to be called before it.
            // Additionally priviledges must be dropped to secure the chroot jail in this case.
            if !f_calls_chdir_and_priviledge_dropping_func(
                program,
                sub,
                chdir_tid,
                &priviledge_dropping_tids[..],
            ) {
                cwe_warnings.push(generate_cwe_warning(sub, &callsite_tid));
            }
        }
    }

    cwe_warnings.deduplicate_first_address()
}
