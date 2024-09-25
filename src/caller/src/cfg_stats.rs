use cwe_checker_lib::analysis::graph::{
    call::{CallGraph, CgNode},
    intraprocedural_cfg::IntraproceduralCfg,
};
use cwe_checker_lib::intermediate_representation::{ExtFunctionTid, Program};

use std::collections::HashMap;

use serde::Serialize;

/// Some properties of a program's CFG.
#[derive(Serialize)]
pub struct CfgProperties<'a> {
    internal_fns: HashMap<String, IntFnCfgProperties>,
    external_fns: HashMap<String, ExtFnCfgProperties<'a>>,
}

/// Some properties of an intraprocedural CFG.
#[derive(Serialize, Debug, PartialEq, Eq)]
struct IntFnCfgProperties {
    /// Cyclomatic complexity.
    cyclomatic_complexity: u32,
    /// Control flow flattening score.
    flattening_score: u32,
    /// Number of basic blocks.
    num_bb: u64,
    /// Number of instructions.
    num_insn: u64,
}

impl IntFnCfgProperties {
    fn new(cfg: &IntraproceduralCfg) -> Self {
        Self {
            cyclomatic_complexity: cfg.cyclomatic_complexity(),
            flattening_score: cfg.flattening_score(),
            num_bb: cfg.num_blocks(),
            num_insn: cfg.num_insn(),
        }
    }
}

/// Some properties of an external function in the CFG.
#[derive(Serialize, Debug, PartialEq, Eq)]
struct ExtFnCfgProperties<'a> {
    /// Number of call sites where this function may be called.
    num_cs: u64,
    /// Name of the function.
    name: &'a str,
}

impl<'a> ExtFnCfgProperties<'a> {
    fn new(p: &'a Program, cg: &CallGraph<'_>, f: &ExtFunctionTid) -> Self {
        Self {
            num_cs: cg.callers(f).map(|(_, edge)| edge.num_cs()).sum(),
            name: &p.extern_symbols.get(f).unwrap().name,
        }
    }
}

impl<'a> CfgProperties<'a> {
    /// Computes some CFG properties of the program `p`.
    pub fn new(p: &'a Program) -> Self {
        let cg = CallGraph::new_with_full_cfgs(p);

        let mut internal_fns = HashMap::new();
        let mut external_fns = HashMap::new();

        for f in cg.nodes() {
            match f {
                CgNode::Function(..) if f.is_artificial() => {
                    // Exclude artificial functions.
                }
                CgNode::Function(term, cfg) => {
                    assert_eq!(
                        internal_fns.insert(term.tid.to_string(), IntFnCfgProperties::new(cfg)),
                        None,
                        "Function TIDs are not unique."
                    );
                }
                CgNode::ExtFunction(tid) => {
                    assert_eq!(
                        external_fns.insert(tid.to_string(), ExtFnCfgProperties::new(p, &cg, tid)),
                        None,
                        "Function TIDs are not unique."
                    );
                }
            }
        }

        Self {
            internal_fns,
            external_fns,
        }
    }
}
