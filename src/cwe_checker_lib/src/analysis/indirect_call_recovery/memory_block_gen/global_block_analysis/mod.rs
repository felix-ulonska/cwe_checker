use std::time::Instant;

use ascent::rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use context::{fill_vsa_result_maps, AnalysisContext, State};
use vsa_result::GlobalBlockAnalysisResult;

use crate::{
    analysis::forward_intraprocdural_fixpoint::create_computation,
    intermediate_representation::{Program, RuntimeMemoryImage},
    prelude::ByteSize,
};

mod context;
pub mod taint;
mod value_specialization;
pub mod vsa_result;

pub fn infer_global_ptr(
    program: &Program,
    memory_segments: &RuntimeMemoryImage,
    register_size: ByteSize,
) -> GlobalBlockAnalysisResult {
    program
        .subs
        .par_iter()
        .map(|sub| {
            eprintln!("Started for sub {}", sub.1.name);
            //println!("Start for sub {}", sub.1);
            let start_time = Instant::now();
            let analysis = AnalysisContext::new(program, sub.1);

            let mut compution = create_computation(
                analysis,
                Some(State::new(sub.0.clone(), memory_segments, register_size)),
            );
            compution.compute_with_max_steps(10000);
            if !compution.has_stabilized() {
                eprintln!("Sub: {} did not stabilize!", sub.1.name);
            }

            let started_vsa_result = Instant::now();
            let result = fill_vsa_result_maps(compution);

            eprintln!(
                "Finished sub {}: overall {:02?} and started_vsa_result: {:02?}",
                sub.1.name,
                start_time.elapsed(),
                started_vsa_result.elapsed()
            );

            result
        })
        // For non parallel
        //.fold(GlobalBlockAnalysisResult::new_empty(), |acc, item| {
        //    acc.merge(&item)
        //})
        .fold(
            || GlobalBlockAnalysisResult::new_empty(),
            |acc, item| acc.merge(&item),
        )
        .reduce(
            || GlobalBlockAnalysisResult::new_empty(),
            |acc, item| acc.merge(&item),
        )
}
