use ascent::rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use context::{fill_vsa_result_maps, AnalysisContext, State};
use vsa_result::GlobalBlockAnalysisResult;

use crate::{
    analysis::forward_intraprocdural_fixpoint::create_computation,
    intermediate_representation::{Program, RuntimeMemoryImage},
};

mod context;
mod value_specialization;
pub mod vsa_result;

pub fn infer_global_ptr(program: &Program, memory_segments: &RuntimeMemoryImage) -> GlobalBlockAnalysisResult {
    program.subs.par_iter().map(|sub| {
        let analysis = AnalysisContext::new(program, sub.1);

        let mut compution = create_computation(
            analysis,
            Some(State::new(
                sub.0.clone(),
                memory_segments
            )),
        );
        compution.compute();

        fill_vsa_result_maps(compution)
    }).fold(|| {GlobalBlockAnalysisResult::new_empty()}, |acc, item| {
        acc.merge(&item)
    }).reduce(|| GlobalBlockAnalysisResult::new_empty(), |acc, item| acc.merge(&item))
}
