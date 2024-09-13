//! Dominator computation.
use crate::abstract_domain::{AbstractDomain, CheapToClone};
use crate::analysis::forward_interprocedural_fixpoint;
use crate::analysis::forward_interprocedural_fixpoint::create_computation;
use crate::analysis::graph::intraprocedural_cfg::{BlockIdxs, IntraproceduralCfg};
use crate::analysis::graph::{Graph, Node, NodeIndex};
use crate::analysis::interprocedural_fixpoint_generic::NodeValue;
use crate::intermediate_representation::{Blk, Def, Expression, Jmp, Term, Tid};

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

struct Context<'a> {
    graph: &'a IntraproceduralCfg<'a>,
}

/// Returns a mapping that takes each basic block to the set of its dominators.
///
/// Standard dataflow analysis:
/// Direction:      Forward
/// Property space: Powerset of all blocks.
/// Ordering:       Reverse inclusion.
/// Initial values: The node itself for the entry node. All nodes for all other
///                 nodes.
pub fn compute_dominators<'a>(
    graph: &IntraproceduralCfg<'a>,
) -> BTreeMap<&'a Tid, BTreeSet<&'a Tid>> {
    let ctx = Context { graph };
    let mut cmp = create_computation(ctx, None);
    let entry = graph.entry();

    cmp.set_node_value(entry.0, NodeValue::Value(Dominators::new_single(entry)));
    cmp.compute_with_max_steps(100);

    if !cmp.has_stabilized() {
        panic!("Dominator computation has not stabilized.");
    }

    cmp.node_values()
        .iter()
        .filter_map(|(idx, doms)| match doms {
            NodeValue::CallFlowCombinator { .. } => None,
            NodeValue::Value(doms) => {
                let Some(dominee) = graph.idx_to_blk_tid(*idx) else {
                    // FIXME: This means we have a `NodeValue::Value` at an
                    //   artificial node. Not good. Investigate.
                    return None;
                };
                let dominators = graph
                    .graph()
                    .node_indices()
                    .filter_map(|idx| {
                        if doms.is_dominator(idx) {
                            let Some(dominator) = graph.idx_to_blk_tid(idx) else {
                                // FIXME: This means we have a
                                //   `NodeValue::Value` at an artificial node.
                                //   Not good. Investigate.
                                return None;
                            };
                            Some(dominator)
                        } else {
                            None
                        }
                    })
                    .collect::<BTreeSet<&'a Tid>>();

                Some((dominee, dominators))
            }
        })
        .collect::<BTreeMap<&'a Tid, BTreeSet<&'a Tid>>>()
}

impl<'a> forward_interprocedural_fixpoint::Context<'a> for Context<'a> {
    type Value = Dominators;

    fn get_graph(&self) -> &Graph<'a> {
        self.graph.graph()
    }

    fn merge(&self, value1: &Self::Value, value2: &Self::Value) -> Self::Value {
        value1.merge(value2)
    }

    fn update_def(&self, value: &Self::Value, _def: &Term<Def>) -> Option<Self::Value> {
        Some(value.clone())
    }

    fn update_jump(
        &self,
        value: &Self::Value,
        _jump: &Term<Jmp>,
        _untaken_conditional: Option<&Term<Jmp>>,
        target: &Term<Blk>,
    ) -> Option<Self::Value> {
        let mut new_value = value.clone();

        // Target block is dominated by itself.
        new_value.insert(*self.graph.blk_tid_to_idx(&target.tid).unwrap());

        Some(new_value)
    }

    fn update_call(
        &self,
        _value: &Self::Value,
        _call: &Term<Jmp>,
        _target: &Node,
        _calling_convention: &Option<String>,
    ) -> Option<Self::Value> {
        None
    }

    fn update_return(
        &self,
        _value: Option<&Self::Value>,
        value_before_call: Option<&Self::Value>,
        call_term: &Term<Jmp>,
        _return_term: &Term<Jmp>,
        _calling_convention: &Option<String>,
    ) -> Option<Self::Value> {
        let mut new_value = value_before_call.unwrap().clone();

        // Return-to block is dominated by itself.
        new_value.insert(match &call_term.term {
            Jmp::Call {
                return_: Some(ret_to_tid),
                ..
            } => *self.graph.blk_tid_to_idx(ret_to_tid).unwrap(),
            // Normalization passes ensure that each call returns to somewhere.
            _ => core::unreachable!(),
        });

        Some(new_value)
    }

    fn update_call_stub(&self, value: &Self::Value, call: &Term<Jmp>) -> Option<Self::Value> {
        let mut new_value = value.clone();

        // Return-to block is dominated by itself.
        new_value.insert(match &call.term {
            Jmp::Call {
                return_: Some(ret_to_tid),
                ..
            }
            | Jmp::CallInd {
                return_: Some(ret_to_tid),
                ..
            }
            | Jmp::CallOther {
                return_: Some(ret_to_tid),
                ..
            } => *self.graph.blk_tid_to_idx(ret_to_tid).unwrap(),
            // Framework should only call this function for the above edge
            // types.
            _ => core::unreachable!(),
        });

        Some(new_value)
    }

    fn specialize_conditional(
        &self,
        value: &Self::Value,
        _condition: &Expression,
        _block_before_condition: &Term<Blk>,
        _is_true: bool,
    ) -> Option<Self::Value> {
        Some(value.clone())
    }
}

/// The dominators of a node.
#[derive(Clone, Eq, PartialEq, Default, Debug)]
struct Dominators {
    /// The dominators of a node.
    inner: Arc<DominatorsInner>,
}

impl CheapToClone for Dominators {}

/// The dominators of a basic block.
#[derive(Clone, Eq, PartialEq, Default, Debug)]
enum DominatorsInner {
    /// Basic block is dominated by all basic blocks.
    #[default]
    Bottom,
    /// Basic block is dominated by a subset of all basic blocks.
    Doms(BTreeSet<BlockIdxs>),
    /// Basic block has no dominators. (Should never happen as each block is
    /// dominated by itself.)
    Top,
}

impl AbstractDomain for Dominators {
    fn merge(&self, other: &Self) -> Dominators {
        if self == other {
            return self.clone();
        }

        use DominatorsInner::*;
        match (&*self.inner, &*other.inner) {
            (Bottom, Bottom) | (_, Bottom) | (Top, _) => self.clone(),
            (_, Top) | (Bottom, _) => other.clone(),
            (Doms(a), Doms(b)) => {
                let intersection = a.intersection(b).cloned().collect::<BTreeSet<BlockIdxs>>();

                Dominators {
                    inner: Arc::new(if intersection.is_empty() {
                        Top
                    } else {
                        Doms(intersection)
                    }),
                }
            }
        }
    }

    fn is_top(&self) -> bool {
        matches!(*self.inner, DominatorsInner::Top)
    }
}

impl Dominators {
    /// Returns a new dominator set that only includes the given block.
    fn new_single(idx: BlockIdxs) -> Self {
        let mut doms = BTreeSet::new();
        doms.insert(idx);

        Self {
            inner: Arc::new(DominatorsInner::Doms(doms)),
        }
    }

    /// Inserts the given block into the dominator set.
    fn insert(&mut self, idx: BlockIdxs) {
        use DominatorsInner::*;
        match &*self.inner {
            Bottom => (),
            Top => {
                let mut doms = BTreeSet::new();
                doms.insert(idx);

                self.inner = Arc::new(DominatorsInner::Doms(doms));
            }
            // Technically incorrect since we do not handle the case when we
            // arrive at `Bottom`.
            Doms(doms) if !doms.contains(&idx) => {
                let doms = Arc::make_mut(&mut self.inner);
                if let Doms(doms) = doms {
                    doms.insert(idx);
                }
            }
            _ => (),
        }
    }

    /// Returns true iff `idx` is the start index of a block that is in this
    /// dominator set.
    pub fn is_dominator(&self, idx: NodeIndex) -> bool {
        use DominatorsInner::*;
        match &*self.inner {
            Bottom => true,
            Top => false,
            Doms(doms) => doms.iter().any(|(blk_start, _)| *blk_start == idx),
        }
    }
}
