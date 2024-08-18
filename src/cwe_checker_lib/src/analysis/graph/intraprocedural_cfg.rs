#![allow(unreachable_code)]
#![allow(dead_code)]
#![allow(unused_imports)]

use crate::intermediate_representation::{Blk, Jmp, Program, Sub as Function, Term, Tid};

use crate::analysis::graph::{Edge, Graph as Cfg, Node, NodeIndex};
use crate::intermediate_representation::SinkType;

use std::collections::{BTreeMap, HashMap, HashSet};

/// Pair of block start and block end nodes for a single basic block.
type BlockIdxs = (NodeIndex, NodeIndex);

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
                    for end_node_idx in b
                        .indirect_jmp_targets
                        .iter()
                        .map(|t| self.blk_tid_to_idx_map.get(t).unwrap().0)
                    {
                        self.graph
                            .add_edge(start_node_idx, end_node_idx, Edge::Jump(j, None));
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

pub struct IntraproceduralCfg<'a> {
    graph: Cfg<'a>,
    blk_tid_to_idx_map: HashMap<&'a Tid, BlockIdxs>,
    entry: BlockIdxs,
    calls: Vec<BlockIdxs>,
    ext_calls: Vec<BlockIdxs>,
    sinks: Vec<(SinkType, BlockIdxs)>,
}

impl<'a> IntraproceduralCfg<'a> {
    pub fn new(program: &'a Program, f: &'a Term<Function>) -> Self {
        IntraproceduralCfgBuilder::new(program, f).build()
    }
}
