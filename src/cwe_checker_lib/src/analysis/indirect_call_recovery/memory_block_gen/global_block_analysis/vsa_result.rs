use std::{collections::HashMap, fmt::Display};

use crate::{
    abstract_domain::{AbstractLocation, DomainMap, TryToInterval, UnionMergeStrategy},
    intermediate_representation::Variable,
    prelude::Tid,
};

use super::context::Data;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RegisterState {
    /// Maps a register variable to the data known about its content.
    /// A variable not contained in the map has value `Data::Top(..)`, i.e. nothing is known about its content.
    pub register: DomainMap<Variable, Data, UnionMergeStrategy>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct GlobalBlockAnalysisResult {
    /// Maps the TIDs of assignment, load or store [`Def`] instructions to the computed value data.
    /// The map will be filled after the fixpoint computation finished.
    values_at_defs: HashMap<Tid, Data>,
    /// Maps the TIDs of load or store [`Def`] instructions to the computed address data.
    /// The map will be filled after the fixpoint computation finished.
    addresses_at_defs: HashMap<Tid, Data>,
    /// Maps certain TIDs like the TIDs of [`Jmp`] instructions to the pointer inference state at that TID.
    /// The map will be filled after the fixpoint computation finished.
    states_at_tids: HashMap<Tid, RegisterState>,
}

impl GlobalBlockAnalysisResult {
    pub fn new(
        values_at_defs: HashMap<Tid, Data>,
        addresses_at_defs: HashMap<Tid, Data>,
        states_at_tids: HashMap<Tid, RegisterState>,
    ) -> GlobalBlockAnalysisResult {
        GlobalBlockAnalysisResult {
            values_at_defs,
            addresses_at_defs,
            states_at_tids,
        }
    }
    pub fn new_empty() -> GlobalBlockAnalysisResult {
        GlobalBlockAnalysisResult {
            values_at_defs: HashMap::new(),
            addresses_at_defs: HashMap::new(),
            states_at_tids: HashMap::new(),
        }
    }

    pub fn merge(&self, other: &GlobalBlockAnalysisResult) -> GlobalBlockAnalysisResult {
        let mut new_self = self.clone();
        new_self.states_at_tids.extend(other.states_at_tids.clone());
        new_self
            .addresses_at_defs
            .extend(other.addresses_at_defs.clone());
        new_self.values_at_defs.extend(other.values_at_defs.clone());

        new_self
    }
}

pub trait SmallVsaResult {
    /// The type of the returned values.
    /// Usually this should be an [`AbstractDomain`](crate::abstract_domain::AbstractDomain),
    /// although this is not strictly required.
    type ValueDomain;

    /// Return the value stored for write instructions, the value read for read instructions or the value assigned for assignments.
    fn eval_value_at_def(&self, def_tid: &Tid) -> Option<Self::ValueDomain>;

    /// Return the value of the address where something is read or written for read or store instructions.
    fn eval_address_at_def(&self, def_tid: &Tid) -> Option<Self::ValueDomain>;
}

/// Implementation of the [`VsaResult`] trait for providing other analyses with an easy-to-use interface
/// to use the value set and points-to analysis results of the GlobalBlockAnalysis.
impl<'a> SmallVsaResult for GlobalBlockAnalysisResult {
    type ValueDomain = Data;

    /// Return the value of the address at the given read or store instruction.
    fn eval_address_at_def(&self, def_tid: &Tid) -> Option<Data> {
        self.addresses_at_defs.get(def_tid).cloned()
    }

    /// Return the assigned value for store or assignment instructions or the value read for load instructions.
    fn eval_value_at_def(&self, def_tid: &Tid) -> Option<Data> {
        self.values_at_defs.get(def_tid).cloned()
    }
}

impl Display for GlobalBlockAnalysisResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (place, addrs) in self.addresses_at_defs.clone() {
            writeln!(f, "Place: {}", place)?;
            if let Ok(interval) = addrs.try_to_offset_interval() {
                writeln!(f, "{}: {:?}", place, interval)?;
            } else {
                writeln!(f, "{}: {:?}", place, addrs)?;
            }
            if let Some(stack_val) = addrs.get_relative_values().iter().find_map(|rel_val| {
                if let AbstractLocation::Register(var) = rel_val.0.get_location() {
                    if var.name.contains("RSP") {
                        Some(rel_val.1)
                    } else {
                        None
                    }
                } else {
                    None
                }
            }) {
                if let Ok(stack_val) = stack_val.try_to_interval() {
                    write!(f, "Stk: {}", place)?;
                    writeln!(
                        f,
                        "[{}-{}]",
                        stack_val.start.try_to_i64().unwrap(),
                        stack_val.end.try_to_i64().unwrap()
                    )?;
                }
            }
        }
        writeln!(f, "VALUES")?;
        for (place, addrs) in self.values_at_defs.clone() {
            if let Ok(interval) = addrs.try_to_offset_interval() {
                writeln!(f, "{}: {:?}", place, interval)?;
            } else {
                writeln!(f, "{}: {:?}", place, addrs)?;
            }
            if let Some(stack_val) = addrs.get_relative_values().iter().find_map(|rel_val| {
                if let AbstractLocation::Register(var) = rel_val.0.get_location() {
                    if var.name.contains("RSP") {
                        Some(rel_val.1)
                    } else {
                        None
                    }
                } else {
                    None
                }
            }) {
                writeln!(f, "Stk: {}: {:?}", place, stack_val.try_to_interval())?;
                if let Ok(stack_val) = stack_val.try_to_interval() {
                    write!(f, "Stk: {}", place)?;
                    writeln!(
                        f,
                        "[{}-{}]",
                        stack_val.start.try_to_i64().unwrap(),
                        stack_val.end.try_to_i64().unwrap()
                    )?;
                }
            }
        }
        Ok(())
    }
}
