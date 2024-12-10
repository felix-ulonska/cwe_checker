//! Intraprocedural control flow graphs.
//!
//! Intraprocedural CFGs use the same nodes and edges as their big brother,
//! the [interprocedural CFG]. They are useful for tasks where it is not
//! necessary to construct a full-blown whole-program CFG. Reusing the same
//! types also allows us to use the same dataflow analysis infrastructure for
//! both kinds of CFGs. It may also allow us to merge multiple intraprocedural
//! CFGs into an interprocedural CFG in the future.
//!
//! [interprocedural CFG]: super::Graph
use crate::analysis::graph::{Edge, Graph as Cfg, Node, NodeIndex};
use crate::intermediate_representation::{Blk, Jmp, Program, SinkType, Sub as Function, Term, Tid};

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

mod dom;
mod natural_loops;
mod properties;
use dom::*;
use natural_loops::*;

/// Pair of block start and block end nodes for a single basic block.
pub type BlockIdxs = (NodeIndex, NodeIndex);

/// Builder for an intraprocedural CFG.
struct IntraproceduralCfgBuilder<'a> {
    /// Graph we build.
    graph: Cfg<'a>,
    /// Function that we build the CFG for.
    function: &'a Term<Function>,
    /// Get from blocks to nodes in constant time.
    blk_tid_to_idx_map: HashMap<&'a Tid, BlockIdxs>,
    /// All functions in the binary.
    fns: &'a BTreeMap<Tid, Term<Function>>,
    /// All imported functions.
    ext_fns: HashSet<&'a Tid>,
    /// Entry point of the function.
    entry: BlockIdxs,
    /// All blocks that end in a call to an internal function.
    calls: Vec<BlockIdxs>,
    /// All blocks that end in a call to an external function.
    ext_calls: Vec<BlockIdxs>,
    /// The artificial sink block, if there is one.
    artificial_sink: Option<BlockIdxs>,
    /// The artificial return target, if there is one.
    artificial_return_target: Option<BlockIdxs>,
    /// All control flow sinks with their type.
    sinks: Vec<(SinkType, BlockIdxs)>,
}

impl<'a> IntraproceduralCfgBuilder<'a> {
    fn new(program: &'a Program, f: &'a Term<Function>) -> Self {
        Self {
            graph: Cfg::new(),
            function: f,
            fns: &program.subs,
            blk_tid_to_idx_map: HashMap::new(),
            ext_fns: program.extern_symbols.keys().collect(),
            // Note: Placeholder.
            entry: (NodeIndex::new(0), NodeIndex::new(1)),
            calls: Vec::with_capacity(0),
            ext_calls: Vec::with_capacity(0),
            artificial_sink: None,
            artificial_return_target: None,
            sinks: Vec::with_capacity(0),
        }
    }

    fn build(mut self) -> IntraproceduralCfg<'a> {
        // Add all block nodes, and edges connecting block-start with block-end.
        // Builds the map, call sites, and sinks.
        for b in self.function.blocks() {
            self.add_block(b);
        }

        // USE INVARIANT: Entry point is always the first block.
        self.entry = *self
            .blk_tid_to_idx_map
            .get(&self.function.blocks.first().unwrap().tid)
            .unwrap();

        // Add edges for control flow transfers between blocks.
        // Insert special nodes and edges for internal calls.
        for (b, j1, j2) in self.function.blocks().map(|b| {
            let mut jmps_iter = b.jmps();
            (b, jmps_iter.next().unwrap(), jmps_iter.next())
        }) {
            self.add_jump(b, j1, j2);
        }

        IntraproceduralCfg {
            graph: self.graph,
            blk_tid_to_idx_map: self.blk_tid_to_idx_map,
            entry: self.entry,
            calls: self.calls,
            ext_calls: self.ext_calls,
            sinks: self.sinks,
            dominators: None,
            natural_loops: None,
        }
    }

    fn add_jump(&mut self, b: &'a Term<Blk>, j1: &'a Term<Jmp>, j2: Option<&'a Term<Jmp>>) {
        let start_node_idx = self.blk_tid_to_idx_map.get(&b.tid).unwrap().1;
        match (j1, j2) {
            // Conditional jumps.
            (
                Term {
                    term:
                        Jmp::CBranch {
                            target: cond_target,
                            ..
                        },
                    ..
                },
                Some(Term {
                    term: Jmp::Branch(ft_target),
                    ..
                }),
            ) => {
                let cond_end_node = self.blk_tid_to_idx_map.get(cond_target).unwrap().0;
                let cond_edge = Edge::Jump(j1, None);
                self.graph
                    .add_edge(start_node_idx, cond_end_node, cond_edge);

                let ft_end_node = self.blk_tid_to_idx_map.get(ft_target).unwrap().0;
                let ft_edge = Edge::Jump(j2.unwrap(), Some(j1));
                self.graph.add_edge(start_node_idx, ft_end_node, ft_edge);
            }
            // All other jumps.
            (j, None) => match &j.term {
                // Calls to internal functions.
                Jmp::Call {
                    target,
                    return_: Some(return_target),
                } if !self.ext_fns.contains(target) => {
                    let end_node_idx = self.blk_tid_to_idx_map.get(return_target).unwrap().0;
                    let called_fn = self.fns.get(target).unwrap();
                    let Node::BlkStart(return_to_blk, _) = self.graph[end_node_idx] else {
                        panic!()
                    };

                    let cs_node_idx = self.graph.add_node(Node::CallSource {
                        source: (b, self.function),
                        target: (called_fn.blocks.first().unwrap(), called_fn),
                    });
                    // Add one CR node, add rest when piecing together
                    // interprocedural graph.
                    let cr_node_idx = self.graph.add_node(Node::CallReturn {
                        call: (b, self.function),
                        return_: (return_to_blk, self.function),
                    });
                    // Do not add `Call` and `CrReturnStub` edges. Add when
                    // piecing together interprocedural graph.
                    self.graph
                        .add_edge(start_node_idx, cs_node_idx, Edge::CallCombine(j));
                    self.graph
                        .add_edge(cs_node_idx, cr_node_idx, Edge::CrCallStub);
                    self.graph
                        .add_edge(cr_node_idx, end_node_idx, Edge::ReturnCombine(j));
                }
                // Plain jumps.
                Jmp::Branch(target) => {
                    let end_node_idx = self.blk_tid_to_idx_map.get(target).unwrap().0;
                    self.graph
                        .add_edge(start_node_idx, end_node_idx, Edge::Jump(j, None));
                }
                // Calls to external functions, indirect calls and special
                // instructions.
                Jmp::Call {
                    return_: Some(return_target),
                    ..
                }
                | Jmp::CallInd {
                    return_: Some(return_target),
                    ..
                }
                | Jmp::CallOther {
                    return_: Some(return_target),
                    ..
                } => {
                    let end_node_idx = self.blk_tid_to_idx_map.get(return_target).unwrap().0;
                    self.graph
                        .add_edge(start_node_idx, end_node_idx, Edge::ExternCallStub(j));
                }
                // Indirect branches.
                Jmp::BranchInd(_) => {
                    if let Some(indirect_jump_targets) = b.ind_jump_targets() {
                        for end_node_idx in
                            indirect_jump_targets.map(|t| self.blk_tid_to_idx_map.get(t).unwrap().0)
                        {
                            self.graph
                                .add_edge(start_node_idx, end_node_idx, Edge::Jump(j, None));
                        }
                    }
                }
                // No interprocedural edges.
                Jmp::Return(_) => (),
                _ => panic!("Malformed jump encountered."),
            },
            _ => panic!("Malformed jump encountered."),
        }
    }

    fn add_block(&mut self, block: &'a Term<Blk>) -> BlockIdxs {
        let blk_start_node = Node::BlkStart(block, self.function);
        let blk_end_node = Node::BlkEnd(block, self.function);
        let blk_edge = Edge::Block;

        // Update the graph.
        let idxs = (
            self.graph.add_node(blk_start_node),
            self.graph.add_node(blk_end_node),
        );
        self.graph.add_edge(idxs.0, idxs.1, blk_edge);

        // Update the map.
        self.blk_tid_to_idx_map.insert(&block.tid, idxs);

        // Update the call sites.
        if let Some(call_targets) = block.get_call_targets() {
            if call_targets.iter().any(|f| self.ext_fns.contains(f)) {
                self.ext_calls.push(idxs);
            } else {
                self.calls.push(idxs);
            }
        }

        // Update the sinks.
        match block.get_sink_type() {
            Some(SinkType::ArtificialSink) => {
                // CHECK INVARIANT: There are zero or one artificial sink blocks
                // per function.
                assert!(self.artificial_sink.is_none());

                self.artificial_sink = Some(idxs);
                self.sinks.push((SinkType::ArtificialSink, idxs));
            }
            Some(SinkType::ArtificialReturnTarget) => {
                // CHECK INVARIANT: There are zero or one artificial return
                // targets per funtion.
                assert!(self.artificial_return_target.is_none());

                self.artificial_return_target = Some(idxs);
                self.sinks.push((SinkType::ArtificialReturnTarget, idxs));
            }
            Some(sink_type) => self.sinks.push((sink_type, idxs)),
            None => (),
        }

        idxs
    }
}

/// An intraprocedural control flow graph.
pub struct IntraproceduralCfg<'a> {
    graph: Cfg<'a>,
    /// Mapping from TIDs of blocks in this function to indices of their start
    /// and end nodes in the graph.
    blk_tid_to_idx_map: HashMap<&'a Tid, BlockIdxs>,
    entry: BlockIdxs,
    calls: Vec<BlockIdxs>,
    ext_calls: Vec<BlockIdxs>,
    sinks: Vec<(SinkType, BlockIdxs)>,
    dominators: Option<BTreeMap<&'a Tid, BTreeSet<&'a Tid>>>,
    natural_loops: Option<Vec<NaturalLoop<'a>>>,
}

impl<'a> IntraproceduralCfg<'a> {
    /// Returns the intraprocedural CFG of the given function `f`.
    pub fn new(program: &'a Program, f: &'a Term<Function>) -> Self {
        IntraproceduralCfgBuilder::new(program, f).build()
    }

    /// Returns a reference to the underlying graph object.
    pub fn graph(&self) -> &Cfg<'a> {
        &self.graph
    }

    /// Returns the indices of the nodes corresponding to function entry point.
    pub fn entry(&self) -> BlockIdxs {
        self.entry
    }

    /// Returns all blocks that contain __direct__ function calls to
    /// __internal__ and __external__ functions.
    pub fn call_sites(&self) -> impl Iterator<Item = BlockIdxs> + '_ {
        self.calls.iter().chain(self.ext_calls.iter()).copied()
    }

    /// Returns an iterator over all sink blocks in this function.
    pub fn sinks(&self) -> impl Iterator<Item = &(SinkType, BlockIdxs)> + '_ {
        self.sinks.iter()
    }

    /// Returns a map that takes all __directly__ called __internal__ and
    /// __external__ functions to the number of times that they are called.
    pub fn callees(&self) -> BTreeMap<&'a Tid, u32> {
        let mut callees = BTreeMap::new();

        for callee in self.call_sites().map(|(blk_start, _)| {
            let Jmp::Call { target, .. } = &self.graph[blk_start].get_block().jmps[0].term else {
                panic!();
            };
            target
        }) {
            use std::collections::btree_map::Entry::*;
            match callees.entry(callee) {
                Vacant(e) => {
                    e.insert(1);
                }
                Occupied(e) => *e.into_mut() += 1,
            }
        }

        callees
    }

    /// Returns the number of basic block in this CFG.
    ///
    /// Note that this is not the number of nodes due to block-splitting and
    /// artificial nodes around function calls.
    pub fn num_blocks(&self) -> u64 {
        self.blk_tid_to_idx_map.len() as u64
    }

    /// Returns the total number of instructions (defs and jmps) in this
    /// function.
    pub fn num_insn(&self) -> u64 {
        self.blk_tid_to_idx_map
            .values()
            .map(|blk_idx| self.graph()[blk_idx.0].get_block().num_insn())
            .sum()
    }

    /// Returns the start and end index of this block.
    pub fn blk_tid_to_idx(&self, blk_tid: &Tid) -> Option<&BlockIdxs> {
        self.blk_tid_to_idx_map.get(blk_tid)
    }

    /// Returns the block term of the block with the given [`Tid`].
    pub fn blk_tid_to_term(&self, blk_tid: &Tid) -> Option<&'a Term<Blk>> {
        self.blk_tid_to_idx(blk_tid)
            .map(|idx| self.graph()[idx.0].get_block())
    }

    /// Returns the block [`Tid`] for block start and end nodes.
    pub fn idx_to_blk_tid(&self, idx: NodeIndex) -> Option<&'a Tid> {
        self.graph()[idx].try_get_block().map(|b| &b.tid)
    }

    /// Computes the dominator relation of this CFG.
    ///
    /// Noop if the dominators were already computed.
    pub fn compute_dominators(&mut self) {
        if self.dominators.is_none() {
            self.dominators = Some(compute_dominators(self));
        }
    }

    /// Returns the dominator relation of this CFG.
    pub fn get_dominators(&self) -> Option<&BTreeMap<&'a Tid, BTreeSet<&'a Tid>>> {
        self.dominators.as_ref()
    }

    /// Computes the natural loops in this CFG.
    ///
    /// Noop if the loops were already computed.
    pub fn compute_natural_loops(&mut self) {
        if self.natural_loops.is_none() {
            self.compute_dominators();
            self.natural_loops = Some(compute_natural_loops(self));
        }
    }

    /// Returns the natural loops in this CFG.
    pub fn get_natural_loops(&self) -> Option<&Vec<NaturalLoop<'a>>> {
        self.natural_loops.as_ref()
    }

    /// Computes all optional analyses for this CFG.
    pub fn compute_all_optional_analyses(&mut self) {
        self.compute_dominators();
        self.compute_natural_loops();
    }
}
