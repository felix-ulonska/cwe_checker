// Analysis of global memory, for speration into blocks.
// We use pointer interference results for gaining knowledge about data

use crate::{abstract_domain::{AbstractLocation, BitvectorDomain, DataDomain, IntervalDomain}, analysis::vsa_results::VsaResult, intermediate_representation::Program, prelude::AnalysisResults};



/// We changed the algorithm for global memory. We use the PI and then build a set where no
/// overlapping address ranges.
pub fn build_global_memory_blocks(program: &Program, value_sets: &impl VsaResult<ValueDomain = DataDomain<IntervalDomain>>) {
    //let mut adresses = vec![];
    for sub in &program.subs {
        if sub.1.name == "main" {
            for block in &sub.1.term.blocks {
                //println!("Blk {}", block.tid);
                for def in block.defs() {
                    println!("{}", def);
                    if let Some(address) = value_sets.eval_address_at_def(&def.tid) {
                        if let Some((abstract_location, interval)) = address.get_if_unique_target() {
                            println!("\t: {}; {}", abstract_location, interval);
                            match abtract_location.get_location() {
                            //    AbstractLocation::GlobalAddress { address: _, .. } => {
                            //        adresses.push(interval.clone());
                            //        println!("\t: {}", interval);
                            //    }
                            //    AbstractLocation::GlobalPointer( address, location) => {

                            //    }
                            //    _ => (),
                            //}
                        }
                    } else {
                    }
                }
            }
        }
    }
}

fn detection_of_bounday_canidates(program: &Program) {
}
