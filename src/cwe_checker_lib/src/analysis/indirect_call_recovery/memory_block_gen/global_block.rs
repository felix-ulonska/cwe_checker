// Analysis of global memory, for speration into blocks.
// We use pointer interference results for gaining knowledge about data

use itertools::Itertools;

use crate::{abstract_domain::{AbstractLocation, DataDomain, IntervalDomain, TryToInterval}, analysis::vsa_results::VsaResult, intermediate_representation::Program};

#[derive(Clone)]
struct Interval {
  begin: i64,
  end: i64,
}

/// Reprsents disjunct intervals.
struct GlobalMemorySeperation {
    intervals: Vec<Interval>
}

impl GlobalMemorySeperation {
    fn new(in_intervals: Vec<IntervalDomain>) -> GlobalMemorySeperation {
        // Idea, we iterate sorted over the intervals. We look behind. If the prev and current
        // element overlap, do not create new section.
        let mut intervals = vec![]; 

        let mut new_interval_canidate: Option<Interval> = None;
        
        let intervals_sorted_by_start = in_intervals.iter().map(|interval| interval.try_to_offset_interval().unwrap()).sorted_by_key(|x| x.0).collect_vec();
        for (begin, end) in intervals_sorted_by_start {
            match new_interval_canidate {
                // Case: new_interval_canidate and current to add interval do not overlap
                Some(Interval { begin: existing_begin, end: existing_end}) if existing_end < begin => {
                    intervals.push(Interval { 
                        begin: existing_begin,
                        end: existing_end
                    });
                    new_interval_canidate = Some(Interval { begin, end });
                }
                // Case 2: new_interval_canidate and current interval overlap => extend interval
                Some(ref mut existing_interval) => { 
                    existing_interval.end = end;
                }
                // Case 3: We are in the first iteration, set new_interval_canidate
                None => {
                    new_interval_canidate = Some(Interval {
                        begin, end
                    }
                )}
            } 
        }
        // We are done, we need to add the last canidate
        if let Some(new_interval) = new_interval_canidate { 
            intervals.push(new_interval);
        }

        GlobalMemorySeperation {
            intervals
        }
    }

    /// [index] is the key. Will return the interval which has index within (begin, end)
    pub fn get_interval(&self, index: i64) -> Option<Interval> {
        // TODO: Do fancy bin search here:
        for interval in &self.intervals { 
            if interval.begin <= index && interval.end >= index {
                return Some(interval.clone());
            }
        }
        return None;
    }
}


/// We changed the algorithm for global memory. We use the PI and then build a set where no
/// overlapping address ranges.
pub fn build_global_memory_blocks(program: &Program, value_sets: &impl VsaResult<ValueDomain = DataDomain<IntervalDomain>>) -> GlobalMemorySeperation {
    let mut intervals = vec![];
    for sub in &program.subs {
        if sub.1.name == "main" {
            for block in &sub.1.term.blocks {
                //println!("Blk {}", block.tid);
                for def in block.defs() {
                    println!("{}", def);
                    if let Some(address) = value_sets.eval_address_at_def(&def.tid) {
                        if let Some((abstract_location, interval)) = address.get_if_unique_target() {
                            println!("\t: {}; {}", abstract_location, interval);
                            match abstract_location.get_location() {
                                AbstractLocation::GlobalAddress { address: _, .. } => {
                                    intervals.push(interval.clone());
                                    println!("\t: {}", interval);
                                }
                                // Global Pointer is not inherently useful.
                                AbstractLocation::GlobalPointer( .. ) => { }
                                _ => (),
                            }
                        }
                    }
                }
            }
        }
    }

    GlobalMemorySeperation::new(intervals)
}

#[cfg(test)]
mod tests {
    use apint::ApInt;

    use crate::abstract_domain::{self, IntervalDomain};

    use super::GlobalMemorySeperation;

    fn build_interval(begin: i64, end: i64) -> abstract_domain::IntervalDomain {
        IntervalDomain::from(abstract_domain::Interval {
            start: ApInt::from_i64(begin),
            end: ApInt::from_i64(end),
            stride: 0
        })
    }

    #[test]
    fn test_interval() {
        let intervals = vec![
            build_interval(10, 20),
            build_interval(15, 20),
            build_interval(17, 20),
            build_interval(22, 25),
        ];

        let global_mem = GlobalMemorySeperation::new(intervals);
        assert_eq!(global_mem.intervals.len(), 2);

        let inter = global_mem.get_interval(18).unwrap();
        assert_eq!(inter.begin, 10);
        assert_eq!(inter.end, 20);
    }
}
