//! Call graphs.
use crate::analysis::graph::intraprocedural_cfg::IntraproceduralCfg;
use crate::intermediate_representation::{Jmp, Program, Sub, Term, Tid};
use crate::utils::debug::ToJsonCompact;

use std::collections::HashMap;
use std::fmt;

use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::{EdgeRef, IntoNodeReferences};
use petgraph::Direction;

/// Whole-program call graph.
pub struct CallGraph<'a> {
    /// The underlying graph object.
    graph: DiGraph<CgNode<'a>, CgEdge<'a>>,
    /// Constant-time mapping of function TIDs to node indices.
    fn_tid_to_idx_map: HashMap<&'a Tid, NodeIndex>,
}

impl ToJsonCompact for CallGraph<'_> {
    fn to_json_compact(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();

        let mut node_counts_map = serde_json::Map::new();
        // Mapping of numeric node indices to function TIDs.
        let mut nodes_map = serde_json::Map::new();
        // Mapping of edges to TIDs of call sites.
        let mut edges_map = serde_json::Map::new();

        // Count nodes.
        let total_nodes = self.graph.node_count();
        let mut fn_nodes = 0u64;
        let mut ext_fn_nodes = 0u64;
        for (idx, node) in self.graph.node_references() {
            nodes_map.insert(idx.index().to_string(), node.to_string().into());
            match node {
                CgNode::Function(..) => fn_nodes += 1,
                CgNode::ExtFunction(..) => ext_fn_nodes += 1,
            }
        }
        node_counts_map.insert("total".into(), total_nodes.into());
        node_counts_map.insert("fn".into(), fn_nodes.into());
        node_counts_map.insert("ext_fn".into(), ext_fn_nodes.into());

        for edge in self.graph.edge_references() {
            edges_map.insert(
                format!("{} -> {}", edge.source().index(), edge.target().index()),
                edge.weight().to_string().into(),
            );
        }

        map.insert("node_counts".into(), node_counts_map.into());
        map.insert("nodes".into(), nodes_map.into());
        map.insert("edges".into(), edges_map.into());

        serde_json::Value::Object(map)
    }
}

impl<'a> CallGraph<'a> {
    /// Constructs the call graph of the program `p`.
    pub fn new(p: &'a Program) -> Self {
        CallGraphBuilder::new(p).build()
    }

    /// Constructs the call graph of the program `p`.
    ///
    /// Computes all optional analyses on the intraprocedural CFGs.
    pub fn new_with_full_cfgs(p: &'a Program) -> Self {
        CallGraphBuilder::new(p).full_cfgs(true).build()
    }

    /// Returns an iterator over the nodes of this call graph.
    pub fn nodes<'b>(&'b self) -> impl Iterator<Item = &'b CgNode<'a>> {
        self.graph.node_references().map(|(_, node)| node)
    }

    /// Returns an iterator over all callers of the function `f`.
    pub fn callers<'b>(
        &'b self,
        f: &Tid,
    ) -> impl Iterator<Item = (&'b CgNode<'a>, &'b CgEdge<'a>)> + 'b {
        let fn_idx = self.fn_tid_to_idx_map.get(f).unwrap();

        self.graph
            .edges_directed(*fn_idx, Direction::Incoming)
            .map(|e_ref| {
                let source = e_ref.source();
                (&self.graph[source], e_ref.weight())
            })
    }

    /// Returns an iterator over all callees of the function `f`.
    pub fn callees<'b>(
        &'b self,
        f: &Tid,
    ) -> impl Iterator<Item = (&'b CgNode<'a>, &'b CgEdge<'a>)> + 'b {
        let fn_idx = self.fn_tid_to_idx_map.get(f).unwrap();

        self.graph
            .edges_directed(*fn_idx, Direction::Outgoing)
            .map(|e_ref| {
                let target = e_ref.target();
                (&self.graph[target], e_ref.weight())
            })
    }
}

/// Call graph node.
///
/// Nodes in a call graph correspond to internal or external (aka. imported)
/// functions. Each function has exactly one node.
///
/// Nodes for internal functions include the function term and intraprocedural
/// CFG.
pub enum CgNode<'a> {
    /// Function defined in the program.
    Function(&'a Term<Sub>, Box<IntraproceduralCfg<'a>>),
    /// Function not defined in the program.
    ExtFunction(&'a Tid),
}

impl fmt::Display for CgNode<'_> {
    /// Simply displays the Tid of the function that corresponds to the node.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tid = match self {
            CgNode::Function(Term { tid, .. }, _) => tid,
            CgNode::ExtFunction(tid) => *tid,
        };
        write!(f, "{}", tid)
    }
}

impl<'a> CgNode<'a> {
    /// Returns true iff this node corresponds to an external function.
    pub fn is_external(&self) -> bool {
        matches!(self, CgNode::ExtFunction(..))
    }
}

/// Call graph edge.
///
/// If function `f` may, directly or indirectly, call function `g` the call
/// graph has exactly one edge `f -> g`. Thus, callers can be determined by
/// iterating incoming edges, and callees by iterating outgoing edges.
/// Furthermore, edges include information about all potential call sites in
/// the caller.
#[derive(Default)]
pub struct CgEdge<'a> {
    direct_call_sites: Vec<CallSite<'a>>,
    indirect_call_sites: Vec<CallSite<'a>>,
}

impl fmt::Display for CgEdge<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for direct_call_site in self.direct_call_sites() {
            write!(f, "d:{},", direct_call_site.insn().tid)?
        }
        for indirect_call_site in self.indirect_call_sites() {
            write!(f, "i:{},", indirect_call_site.insn().tid)?
        }
        Ok(())
    }
}

impl<'a> CgEdge<'a> {
    /// Adds the given call site to the edge.
    pub fn add_call_site(&mut self, call_site: CallSite<'a>) -> &mut Self {
        if call_site.indirect {
            self.indirect_call_sites.push(call_site)
        } else {
            self.direct_call_sites.push(call_site)
        }
        self
    }

    /// Returns an iterator over the direct call sites of this edge.
    pub fn direct_call_sites<'b>(&'b self) -> impl Iterator<Item = &'b CallSite<'a>> + 'b {
        self.direct_call_sites.iter()
    }

    /// Returns an iterator over the indirect call sites of this edge.
    pub fn indirect_call_sites<'b>(&'b self) -> impl Iterator<Item = &'b CallSite<'a>> + 'b {
        self.indirect_call_sites.iter()
    }

    /// Returns the total number of call sites represented by this edge.
    pub fn num_cs(&self) -> u64 {
        (self.direct_call_sites.len() + self.indirect_call_sites.len()) as u64
    }

    /// Analyzes the given CFG to construct a mapping from callee `Tid`s to the
    /// corresponding call graph edges.
    fn analyze_callees(cfg: &IntraproceduralCfg<'a>) -> HashMap<&'a Tid, CgEdge<'a>> {
        let mut callee_tid_to_edge_map: HashMap<&'a Tid, CgEdge<'a>> = HashMap::new();

        for (callee_tid, call_site) in cfg.call_sites().flat_map(|(start_idx, _)| {
            let blk = cfg.graph()[start_idx].get_block();
            let blk_callees = blk.get_call_targets().unwrap();
            let call_site = CallSite::from_insn(blk.jmps.first().unwrap());

            blk_callees.into_iter().zip(core::iter::repeat(call_site))
        }) {
            callee_tid_to_edge_map
                .entry(callee_tid)
                .or_default()
                .add_call_site(call_site);
        }

        callee_tid_to_edge_map
    }
}

/// Call site.
#[derive(Clone)]
pub struct CallSite<'a> {
    indirect: bool,
    insn: &'a Term<Jmp>,
}

impl<'a> CallSite<'a> {
    /// Constructs a `CallSite` from the given instruction.
    pub fn from_insn(insn: &'a Term<Jmp>) -> Self {
        debug_assert!(insn.is_call());
        Self {
            indirect: insn.is_indirect_call(),
            insn,
        }
    }

    /// Returns true iff this in an indirect call.
    pub fn is_indirect(&self) -> bool {
        self.indirect
    }

    /// Returns the call instruction.
    pub fn insn(&self) -> &'a Term<Jmp> {
        self.insn
    }
}

/// Builder for [`CallGraph`]s.
struct CallGraphBuilder<'a> {
    /// Underlying graph that we are building.
    graph: DiGraph<CgNode<'a>, CgEdge<'a>>,
    /// Program that we are building the CG for.
    p: &'a Program,
    /// Constant-time mapping of function TIDs to node indices that we are
    /// building.
    fn_tid_to_idx_map: HashMap<&'a Tid, NodeIndex>,
    /// Set of all imported functions.
    ext_fns: Vec<&'a Tid>,
    /// Compute all optional analyses on the intraprocedural CFGs.
    full_cfgs: bool,
}

impl<'a> CallGraphBuilder<'a> {
    /// Returns a new call graph builder for the program `p`.
    fn new(p: &'a Program) -> Self {
        Self {
            graph: DiGraph::new(),
            fn_tid_to_idx_map: HashMap::new(),
            p: &p,
            ext_fns: p.extern_symbols.keys().collect(),
            full_cfgs: false,
        }
    }

    /// Compute all optional analyses on the intraprocedural CFGs.
    fn full_cfgs(mut self, full_cfg: bool) -> Self {
        self.full_cfgs = full_cfg;

        self
    }

    /// Constructs the call graph (expensive).
    fn build(mut self) -> CallGraph<'a> {
        let mut fn_tid_to_callees_map: Vec<(&'a Tid, HashMap<&'a Tid, CgEdge<'a>>)> = Vec::new();

        // Add nodes for external functions.
        for ext_fn_tid in self.ext_fns.iter() {
            let idx = self.graph.add_node(CgNode::ExtFunction(ext_fn_tid));
            self.fn_tid_to_idx_map.insert(ext_fn_tid, idx);
        }

        // Add nodes for internal functions.
        for (fn_tid, fn_term) in self.p.subs.iter() {
            let mut cfg = IntraproceduralCfg::new(self.p, fn_term);

            if self.full_cfgs {
                cfg.compute_all_optional_analyses();
            }

            // Remember edges we need to add later.
            fn_tid_to_callees_map.push((fn_tid, CgEdge::analyze_callees(&cfg)));

            let idx = self
                .graph
                .add_node(CgNode::Function(fn_term, Box::new(cfg)));

            self.fn_tid_to_idx_map.insert(fn_tid, idx);
        }

        // Add edges.
        for (fn_tid, callees) in fn_tid_to_callees_map.into_iter() {
            let idx = self.fn_tid_to_idx_map.get(fn_tid).unwrap();
            for (callee_tid, cg_edge) in callees.into_iter() {
                let callee_idx = self.fn_tid_to_idx_map.get(callee_tid).unwrap();
                self.graph.add_edge(*idx, *callee_idx, cg_edge);
            }
        }

        CallGraph {
            graph: self.graph,
            fn_tid_to_idx_map: self.fn_tid_to_idx_map,
        }
    }
}
