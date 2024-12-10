//! Natural loops.
use crate::analysis::graph::intraprocedural_cfg::IntraproceduralCfg;
use crate::analysis::graph::{Edge, Graph};
use crate::intermediate_representation::Tid;

use std::collections::BTreeSet;
use std::fmt;

use petgraph::visit::EdgeRef;

/// A natural loop in the CFG.
pub struct NaturalLoop<'a> {
    /// Block that controls the loop.
    head: &'a Tid,
    /// Blocks contained in the loop.
    blocks: BTreeSet<&'a Tid>,
}

impl fmt::Display for NaturalLoop<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "head:{}, blocks:", self.head)?;
        for b in self.blocks() {
            write!(f, "{}, ", b)?
        }

        Ok(())
    }
}

impl<'a> NaturalLoop<'a> {
    /// Returns the block that controls the loop.
    pub fn head(&self) -> &'a Tid {
        self.head
    }

    /// Returns the blocks inside the loop.
    pub fn blocks<'b>(&'b self) -> impl Iterator<Item = &'a Tid> + 'b {
        self.blocks.iter().cloned()
    }
}

/// An edge from a block to one of its dominators.
///
/// Such an edge defines a natural loop.
struct BackEdge<'a> {
    tail: &'a Tid,
    /// Block that controls the loop.
    head: &'a Tid,
}

impl<'a> BackEdge<'a> {
    /// Computes the natural loop of this back edge.
    fn natural_loop(&self, cfg: &IntraproceduralCfg<'a>, rev_cfg: &Graph<'_>) -> NaturalLoop<'a> {
        let mut visited = BTreeSet::new();
        visited.insert(cfg.blk_tid_to_idx(self.head).unwrap().0);

        let mut stack = vec![cfg.blk_tid_to_idx(self.tail).unwrap().1];
        while let Some(idx) = stack.pop() {
            visited.insert(idx);
            for idx in rev_cfg.neighbors(idx) {
                if !visited.contains(&idx) {
                    stack.push(idx);
                }
            }
        }

        NaturalLoop {
            head: self.head,
            blocks: visited
                .into_iter()
                // Also removes artificial nodes.
                .filter_map(|idx| cfg.idx_to_blk_tid(idx))
                .collect(),
        }
    }
}

/// Returns the natural loops of this CFG.
///
/// Panics if dominator relation was not computed.
pub fn compute_natural_loops<'a>(cfg: &IntraproceduralCfg<'a>) -> Vec<NaturalLoop<'a>> {
    let doms = cfg.get_dominators().unwrap();
    let back_edges: Vec<BackEdge<'a>> = cfg
        .graph()
        .edge_references()
        .filter_map(|e| {
            let tail = cfg.idx_to_blk_tid(e.source());
            let head = cfg.idx_to_blk_tid(e.target());

            // Due to the way we split blocks into two nodes each `Block` edge
            // would be a back edge.
            if matches!(e.weight(), Edge::Block) {
                return None;
            }

            if let (Some(tail), Some(head)) = (tail, head) {
                if doms
                    .get(tail)
                    .is_some_and(|tail_doms| tail_doms.contains(head))
                {
                    Some(BackEdge { head, tail })
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();

    let mut rev_cfg = cfg.graph().clone();
    rev_cfg.reverse();

    back_edges
        .into_iter()
        .map(|be| be.natural_loop(cfg, &rev_cfg))
        .collect()
}
