// Analysis of global memory, for speration into blocks.
// We use pointer interference results for gaining knowledge about data
//

use std::{collections::HashMap, fmt::Display};

use itertools::Itertools;

use crate::{
    abstract_domain::{AbstractLocation, DataDomain, IntervalDomain, TryToInterval},
    intermediate_representation::{Def, Program, Project},
    prelude::{Term, Tid},
};

use super::global_block_analysis::{analyze_global_blocks::GlobalMemContent, vsa_result::SmallVsaResult};

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct Interval {
    pub begin: i64,
    pub end: i64,
}

impl Display for Interval {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}, {}]@GLOBAL", self.begin, self.end)
    }
}

impl Interval {
    pub fn contains(&self, other: &Interval) -> bool {
        self.begin <= other.begin && other.end <= self.end
    }

    pub fn contains_i64(&self, other: i64) -> bool {
        self.begin <= other && other <= self.end
    }

    pub fn try_from_data_domain(data: DataDomain<IntervalDomain>) -> Option<Self> {
        if let Some((abstract_location, interval)) = data.get_if_unique_target() {
       match abstract_location.get_location() {
                AbstractLocation::GlobalAddress { address: _, .. } => {
                    let Ok(data) = interval.try_to_offset_interval() else {
                        return None;
                    };

                    return Some(Self {
                        begin: data.0,
                        end: data.1,
                    });
                }
                // Global Pointer is not inherently useful.
                AbstractLocation::GlobalPointer(..) => {}
                _ => (),
            }
        }
        None
    }
}

/// Reprsents disjunct intervals.
pub struct GlobalMemorySeperation {
    intervals: Vec<Interval>,
    map_def_to_interval: HashMap<Tid, Interval>,
    global_mem_content: GlobalMemContent,
}

impl GlobalMemorySeperation {
    fn _get_interval_for_def(&self, def: Term<Def>) -> Option<Interval> {
        self.map_def_to_interval.get(&def.tid).cloned()
    }

    pub fn count_blocks(&self) -> usize {
        self.intervals.iter().unique().count()
    }

    pub fn iter_all_blocks(&self) -> std::slice::Iter<'_, Interval> {
        self.intervals.iter()
    }
}

impl Display for GlobalMemorySeperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Global Mem:\n")?;
        for Interval { begin, end } in &self.intervals {
            write!(f, "\t Section: [{}, {}]", begin, end)?;
        }
        Ok(())
    }
}

/// All Intervals are unique by begin
impl GlobalMemorySeperation {
    // Parses the Vec<IntervalDomain> and constructs disjunct intervals with every overlapping
    // interval.
    fn new(in_intervals: Vec<(Tid, IntervalDomain)>, project: &Project) -> GlobalMemorySeperation {
        // Idea, we iterate sorted over the intervals. We look behind. If the prev and current
        // element overlap, do not create new section.
        let mut intervals = vec![];

        let mut new_interval_canidate: Option<Interval> = None;

        let intervals_sorted_by_start = in_intervals
            .iter()
            .map(|interval| interval.1.try_to_offset_interval())
            .filter(|interval| interval.is_ok())
            .map(|interval| interval.unwrap())
            .sorted_by_key(|x| x.0)
            .collect_vec();
        for (begin, end) in intervals_sorted_by_start {
            match new_interval_canidate {
                // Case: new_interval_canidate and current to add interval do not overlap
                Some(Interval {
                    begin: existing_begin,
                    end: existing_end,
                }) if existing_end < begin => {
                    intervals.push(Interval {
                        begin: existing_begin,
                        end: existing_end,
                    });
                    new_interval_canidate = Some(Interval { begin, end });
                }
                // Case 2: new_interval_canidate and current interval overlap => extend interval
                Some(ref mut existing_interval) => {
                    // Attention: The list is not sorted by end
                    if end > existing_interval.end {
                        existing_interval.end = end;
                    }
                }
                // Case 3: We are in the first iteration, set new_interval_canidate
                None => {
                    new_interval_canidate = Some(Interval { begin, end });
                }
            }
        }
        // We are done, we need to add the last canidate
        if let Some(new_interval) = new_interval_canidate {
            intervals.push(new_interval);
        }

        let mut map_def_to_interval = HashMap::<Tid, Interval>::new();

        for (tid, interval) in in_intervals {
            let Ok(interval) = interval.try_to_offset_interval() else {
                continue;
            };
            let interval = Interval {
                begin: interval.0,
                end: interval.1,
            };
            for test_interval in &intervals {
                if test_interval.contains(&interval) {
                    map_def_to_interval.insert(tid, test_interval.clone());
                    break;
                }
            }
        }

        let global_mem_content = GlobalMemContent::new(project, &intervals);
        GlobalMemorySeperation {
            intervals,
            map_def_to_interval,
            global_mem_content
        }
    }

    pub fn iter_content(&self) -> ascent::hashbrown::hash_map::Iter<'_, Interval, Vec<u64>> {
        self.global_mem_content.iter_content()
    }

    /// Returns interval, if an interval is mapped to def
    pub fn get_interval_of_def(&self, def: Term<Def>) -> Option<Interval> {
        self.map_def_to_interval.get(&def.tid).cloned()
    }

    /// [index] is the key. Will return the interval which has index within (begin, end)
    pub fn get_interval(&self, index: i64) -> Option<Interval> {
        for interval in &self.intervals {
            if interval.begin <= index && interval.end >= index {
                return Some(interval.clone());
            }
        }

        None
    }
}

/// We changed the algorithm for global memory. We use the PI and then build a set where no
/// overlapping address ranges.
pub fn build_global_memory_blocks(
    program: &Program,
    project: &Project,
    value_sets: &impl SmallVsaResult<ValueDomain = DataDomain<IntervalDomain>>,
) -> GlobalMemorySeperation {
    let mut intervals = vec![];
    for sub in &program.subs {
        for block in &sub.1.term.blocks {
            for def in block.defs() {
                if let Some(address) = value_sets.eval_address_at_def(&def.tid) {
                    if let Some((abstract_location, interval)) = address.get_if_unique_target() {
                        match abstract_location.get_location() {
                            AbstractLocation::GlobalAddress { address: _, .. } => {
                                intervals.push((def.tid.clone(), interval.clone()));
                            }
                            // Global Pointer is not inherently useful.
                            AbstractLocation::GlobalPointer(..) => {}
                            _ => (),
                        }
                    }
                }
            }
        }
    }

    GlobalMemorySeperation::new(intervals, project)
}

#[cfg(test)]
mod tests {
    use apint::ApInt;

    use crate::{
        abstract_domain::{self, IntervalDomain}, intermediate_representation::Project, prelude::Tid
    };

    use super::GlobalMemorySeperation;

    fn build_interval(begin: i64, end: i64) -> (Tid, abstract_domain::IntervalDomain) {
        (
            Tid::new("foo"),
            IntervalDomain::from(abstract_domain::Interval {
                start: ApInt::from_i64(begin),
                end: ApInt::from_i64(end),
                stride: 0,
            }),
        )
    }

    #[test]
    fn test_interval() {
        let intervals = vec![
            build_interval(10, 20),
            build_interval(15, 20),
            build_interval(17, 20),
            build_interval(22, 25),
        ];

        let global_mem = GlobalMemorySeperation::new(intervals, &Project::mock_x64());
        assert_eq!(global_mem.intervals.len(), 2);

        let inter = global_mem.get_interval(18).unwrap();
        assert_eq!(inter.begin, 10);
        assert_eq!(inter.end, 20);
    }
}
