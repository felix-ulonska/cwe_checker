//! Some simple graph algorithms.

use std::collections::hash_map::{Entry, HashMap};

use petgraph::prelude::*;
use petgraph::unionfind::UnionFind;
use petgraph::visit::{IntoEdgeReferences, NodeCompactIndexable};

/// Returns the components of the graph `g`.
pub fn components<G>(g: &G) -> Vec<Vec<G::NodeId>>
where
    G: IntoEdgeReferences + NodeCompactIndexable,
{
    let mut vertex_sets = UnionFind::new(g.node_bound());
    for e in g.edge_references() {
        let (h, t) = (e.target(), e.source());
        vertex_sets.union(g.to_index(h), g.to_index(t));
    }
    let representatives = vertex_sets.into_labeling();
    let mut sets: HashMap<usize, Vec<G::NodeId>> = HashMap::new();
    for (index, repr) in representatives.iter().enumerate() {
        match sets.entry(*repr) {
            Entry::Vacant(e) => {
                e.insert(vec![g.from_index(index)]);
            }
            Entry::Occupied(e) => e.into_mut().push(g.from_index(index)),
        }
    }

    sets.into_values().collect()
}
