//! Some simple CFG properties.

use crate::analysis::graph::intraprocedural_cfg::IntraproceduralCfg;

use petgraph::algo::connected_components;

impl<'a> IntraproceduralCfg<'a> {
    /// Returns the cyclomatic complexity of the given CFG.
    pub fn cyclomatic_complexity(&self) -> u32 {
        let p = connected_components(self.graph()) as i64;
        let e = self.graph().edge_count() as i64;
        let n = self.graph().node_count() as i64;

        let cc = e - n + 2 * p;

        if cc >= 1 && cc < u32::MAX as i64 {
            cc as u32
        } else {
            panic!(
                "CFG with invalid cyclomatic complexity: cc={}, e={}, n={}, p={}",
                cc, e, n, p
            )
        }
    }

    /// Returns a number indicating the likeliness that this CFG was obfuscated
    /// by control flow flattening.
    ///
    /// This works by first finding the natural loop whose header dominates the
    /// most other blocks. The flattening score is then defined as the fraction
    /// of blocks dominated by this header times the maximum score.
    ///
    /// See this [blog post] for more information. The score is between 0 and
    /// 1_000_000 inclusive.
    ///
    /// Expects that loops and dominators are computed.
    ///
    /// [blog post]: https://synthesis.to/2021/03/03/flattening_detection.html
    pub fn flattening_score(&self) -> u32 {
        const MAX_SCORE: usize = 1_000_000;

        let doms = self.get_dominators().expect("Compute dominators first.");
        // Compute the maximum number of blocks dominated by a block that
        // controls a natural loop.
        let tmp = self
            .get_natural_loops()
            .expect("Compute loops first.")
            .iter()
            .map(|l| {
                let head = l.head();
                // Get number of nodes dominated by this loop head.
                doms.get(head).unwrap().len()
            })
            .max()
            // Score is 0 if there are no loops.
            .unwrap_or(0);

        ((tmp * MAX_SCORE) / self.num_blocks() as usize) as u32
    }
}
