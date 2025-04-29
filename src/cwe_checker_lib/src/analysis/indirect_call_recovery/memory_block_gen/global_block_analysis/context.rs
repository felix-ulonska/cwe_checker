use std::{
    collections::{BTreeMap, HashMap},
    fmt::Display,
};

use apint::ApInt;
use ascent::hashbrown::HashSet;
use itertools::Itertools;

use crate::{
    abstract_domain::{
        AbstractDomain, AbstractIdentifier, AbstractLocation, DataDomain, DomainMap, Interval,
        IntervalDomain, RegisterDomain, SizedDomain, TryToBitvec, TryToInterval,
        UnionMergeStrategy,
    },
    analysis::{
        fixpoint::Computation,
        forward_intraprocdural_fixpoint::{Context, GeneralizedContext},
        graph::{intraprocedural_cfg::IntraproceduralCfg, Node},
    },
    intermediate_representation::{
        BinOpType, Def, Expression, Program, RuntimeMemoryImage, Sub, Variable,
    },
    prelude::{Bitvector, BitvectorExtended, ByteSize, Term, Tid},
    utils::binary::MemorySegment,
};

use super::{taint::simple_taint, vsa_result::GlobalBlockAnalysisResult};

pub type ValueDomain = IntervalDomain;

/// The abstract domain type for representing register values.
pub type Data = DataDomain<ValueDomain>;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MemorySegmentWithInterval<'a> {
    interval: Interval,
    segment: &'a MemorySegment,
}

// A lot of the following is taken from the pointer interference, however this only includes the
// necassary to determine intereger values.
/// Contains all information known about the state of a program at a specific point of time.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct State<'a> {
    /// Maps a register variable to the data known about its content.
    /// A variable not contained in the map has value `Data::Top(..)`, i.e. nothing is known about its content.
    pub register: DomainMap<Variable, Data, UnionMergeStrategy>,
    memory_segments: Vec<MemorySegmentWithInterval<'a>>,
    function_tid: Tid,
    var_size: ByteSize,
}

impl<'a> State<'a> {
    pub fn new(
        function_tid: Tid,
        runtime_memory_image: &'a RuntimeMemoryImage,
        variable_size: ByteSize,
    ) -> State {
        let register = DomainMap::from(BTreeMap::new());
        let mut memory_segements = vec![];
        for segment in &runtime_memory_image.memory_segments {
            memory_segements.push(MemorySegmentWithInterval {
                interval: Interval::new(
                    segment.base_address.into(),
                    (segment.base_address + segment.bytes.len() as u64).into(),
                    1,
                ),
                segment,
            });
        }
        State {
            register,
            memory_segments: memory_segements,
            function_tid,
            var_size: variable_size,
        }
    }

    /// Get the value of a register or Top() if no value is known.
    pub fn get_register(&self, variable: &Variable) -> Data {
        if let Some(data) = self.register.get(variable) {
            data.clone()
        } else {
            //was: Data::new_top(variable.size)
            Data::new_top(variable.size)
        }
    }

    /// Set the value of a register.
    pub fn set_register(&mut self, variable: &Variable, value: Data) {
        if !value.is_top() {
            self.register.insert(variable.clone(), value);
        } else {
            self.register.remove(variable);
        }
    }

    /// Evaluate expression on the given state and write the result to the target register.
    pub fn handle_register_assign(&mut self, target: &Variable, expression: &Expression) {
        self.set_register(target, self.eval(expression))
    }

    /// Evaluate the value of an expression in the current state.
    pub fn eval(&self, expression: &Expression) -> Data {
        let result = self.eval_recursive(expression);
        let result = self.replace_if_global_pointer(result);

        result
    }

    /// Get the abstract ID of the global memory object corresponding to this function.
    pub fn get_global_mem_id(&self) -> AbstractIdentifier {
        AbstractIdentifier::new(
            // TODO: this is probaly the wrong one
            self.function_tid.clone(),
            AbstractLocation::GlobalAddress {
                address: 0,
                size: self.var_size.clone(),
            },
        )
    }

    pub fn is_global_mem(&self, constant: &ApInt) -> bool {
        for segment in &self.memory_segments {
            if segment.interval.bytesize() != constant.bytesize() {
                continue;
            }
            if segment.interval.contains(constant) {
                return true;
            }
        }
        false
    }

    fn get_global_const_vals(&self, value: &Expression) -> Vec<ApInt> {
        match value {
            Expression::Var(_) | Expression::Unknown { .. } | Expression::Phi(_) => vec![],
            Expression::Const(constval) => {
                if self.is_global_mem(constval) {
                    vec![constval.clone()]
                } else {
                    vec![]
                }
            }
            Expression::BinOp { lhs, rhs, .. } => [
                self.get_global_const_vals(&*lhs),
                self.get_global_const_vals(&*rhs),
            ]
            .concat(),
            Expression::UnOp { arg, .. }
            | Expression::Cast { arg, .. }
            | Expression::Subpiece { arg, .. } => self.get_global_const_vals(&*arg),
        }
    }

    fn get_pab(&self, value: &Expression) -> Option<Data> {
        let mut min_val: Option<ApInt> = None;
        for const_val in self.get_global_const_vals(value) {
            if min_val == None
                || min_val.clone().unwrap().try_to_u64().unwrap() > const_val.try_to_u64().unwrap()
            {
                min_val = Some(const_val);
            }
        }

        if let Some(min_val) = min_val {
            return Some(self.replace_if_global_pointer(min_val.into()));
        }
        None
    }

    fn extend_interval_by_pab(&self, expr: &Expression, value: &Data) -> Data {
        if let Some(pab) = self.get_pab(expr) {
            if value.bytesize() == pab.bytesize() {
                value.merge(&pab)
            } else {
                value.clone()
            }
        } else {
            value.clone()
        }
    }

    /// If the input value is a constant that is also the address of a global variable known to the function
    /// then replace it with a value relative to the global memory ID of the state.
    fn replace_if_global_pointer(&self, mut value: Data) -> Data {
        if let Ok(constant) = value.try_to_offset() {
            for segment in &self.memory_segments {
                if segment.interval.contains(&Bitvector::from_i64(constant)) {
                    value = Data::from_target(
                        self.get_global_mem_id(),
                        value.try_to_interval().unwrap().into(),
                    );
                }
            }
        }
        value
    }

    /// Recursively evaluate the value of an expression in the current state.
    /// Should only be called by [`State::eval`].
    fn eval_recursive(&self, expression: &Expression) -> Data {
        use Expression::*;
        let output = match expression {
            Var(variable) => self.get_register(variable),
            Const(bitvector) => {
                return self.replace_if_global_pointer(bitvector.clone().into());
            }
            BinOp { op, lhs, rhs } => {
                if *op == BinOpType::IntXOr && lhs == rhs {
                    // the result of `x XOR x` is always zero.
                    return Bitvector::zero(apint::BitWidth::from(lhs.bytesize())).into();
                }
                let (left, right) = (self.eval_recursive(lhs), self.eval_recursive(rhs));
                let output = left.bin_op(*op, &right);
                let output = self.extend_interval_by_pab(lhs, &output);
                let output = self.extend_interval_by_pab(rhs, &output);

                output
            }
            UnOp { op, arg } => self.eval_recursive(arg).un_op(*op),
            Cast { op, size, arg } => self.eval_recursive(arg).cast(*op, *size),
            Unknown {
                description: _,
                size,
            } => Data::new_top(*size),
            Subpiece {
                low_byte,
                size,
                arg,
            } => {
                let result = self.eval_recursive(arg).subpiece(*low_byte, *size);
                result
            }
            Phi(inputs) => {
                let inputs = inputs
                    .iter()
                    // Ensure that values are set, otherwise not yet inited value would inject a top
                    // value
                    .filter(|input| {
                        let Some(reg) = self.register.get(input) else {
                            return false;
                        };
                        !reg.get_relative_values().is_empty() || reg.get_absolute_value().is_some()
                    })
                    .collect_vec();
                if inputs.len() == 0 {
                    Data::new_empty(self.var_size)
                } else if inputs.len() == 1 {
                    self.get_register(inputs[0])
                } else {
                    let mut merged_data = self.get_register(inputs[0]).clone();
                    for input in inputs {
                        merged_data = merged_data.merge(&self.get_register(input));
                    }
                    merged_data
                }
            }
        };

        output
    }
}

fn is_interval_global(val: &Data) -> bool {
    val.get_if_unique_target().is_some()
}

/// Fill the various result maps of `self` that are needed for the [`VsaResult`](crate::analysis::vsa_results::VsaResult) trait implementation.
pub fn fill_vsa_result_maps<'b>(
    computation: Computation<GeneralizedContext<'b, AnalysisContext<'b>>>,
) -> GlobalBlockAnalysisResult {
    let mut values_at_defs = HashMap::new();
    let mut addresses_at_defs = HashMap::new();
    let states_at_tids = HashMap::new();

    let context = computation.get_context().get_context();
    let graph = computation.get_graph();
    for node in graph.node_indices() {
        match graph[node] {
            Node::BlkStart(blk, _sub) => {
                let node_state = match computation.get_node_value(node) {
                    Some(value) => value,
                    _ => continue,
                };
                let mut state = node_state.clone();
                for def in &blk.term.defs {
                    //println!("Def: {}", def);
                    match &def.term {
                        Def::Assign { var: _var, value } => {
                            let evaled = state.eval(value);
                            let evaled = state.extend_interval_by_pab(value, &evaled);
                            if is_interval_global(&evaled) {
                                values_at_defs.insert(def.tid.clone(), evaled);
                            }
                        }
                        Def::Load { var: _var, address } => {
                            let evaled = state.eval(address);
                            let evaled = state.extend_interval_by_pab(address, &evaled);
                            if is_interval_global(&evaled) {
                                addresses_at_defs.insert(def.tid.clone(), evaled);
                            }
                        }
                        Def::Store { address, value } => {
                            let evaled = state.eval(value);
                            let evaled = state.extend_interval_by_pab(value, &evaled);
                            if is_interval_global(&evaled) {
                                values_at_defs.insert(def.tid.clone(), evaled);
                            }
                            let evaled = state.eval(address);
                            if is_interval_global(&evaled) {
                                addresses_at_defs.insert(def.tid.clone(), evaled);
                            }
                        }
                    }
                    state = match context.update_def(&state, def) {
                        Some(new_state) => new_state,
                        None => break,
                    }
                }
            }
            Node::BlkEnd(_blk, _sub) => {}
            Node::CallSource { .. } => (),
            Node::CallReturn {
                call: (_caller_blk, _caller_sub),
                return_: _,
            } => (),
        }
    }

    GlobalBlockAnalysisResult::new(values_at_defs, addresses_at_defs, states_at_tids)
}

impl Display for State<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (reg, value) in self.register.iter() {
            let Some(value) = value.get_absolute_value() else {
                if let Ok(interval) = value.try_to_offset_interval() {
                    write!(f, "{}: [{}-{}]", reg.name, interval.0, interval.1)?;
                } else {
                    write!(f, "{}: {:?}", reg.name, value)?;
                }
                continue;
            };
            write!(f, "{}:{}", reg.name, value)?;
        }
        Ok(())
    }
}

impl AbstractDomain for State<'_> {
    /// Merge two states
    fn merge(&self, other: &Self) -> Self {
        State {
            register: self.register.merge(&other.register),
            memory_segments: self.memory_segments.clone(),
            function_tid: self.function_tid.clone(),
            var_size: self.var_size,
        }
    }

    /// A state has no *Top* element
    fn is_top(&self) -> bool {
        false
    }
}

pub struct AnalysisContext<'a> {
    cfg: IntraproceduralCfg<'a>,
    taint: HashSet<&'a Variable>,
}

impl<'a> AnalysisContext<'a> {
    pub fn new(program: &'a Program, sub: &'a Term<Sub>) -> AnalysisContext<'a> {
        let cfg = IntraproceduralCfg::new(program, sub);
        let taint = simple_taint(sub);

        AnalysisContext { cfg, taint }
    }
}

impl<'a> Context<'a> for AnalysisContext<'a> {
    type Value = State<'a>;

    fn get_graph(&self) -> &crate::analysis::graph::Graph<'a> {
        &self.cfg.graph()
    }

    fn merge(&self, value1: &Self::Value, value2: &Self::Value) -> Self::Value {
        value1.merge(value2)
    }

    fn update_def(
        &self,
        state: &Self::Value,
        def: &crate::prelude::Term<crate::intermediate_representation::Def>,
    ) -> Option<Self::Value> {
        let mut new_state = state.clone();

        match &def.term {
            Def::Store { .. } => Some(new_state),
            Def::Assign { var, value } => {
                if self.taint.contains(var) {
                    new_state.handle_register_assign(var, value);
                }
                Some(new_state)
            }
            Def::Load { .. } => Some(new_state),
        }
    }

    fn update_jump(
        &self,
        state: &Self::Value,
        _jump: &crate::prelude::Term<crate::intermediate_representation::Jmp>,
        _untaken_conditional: Option<
            &crate::prelude::Term<crate::intermediate_representation::Jmp>,
        >,
        _target: &crate::prelude::Term<crate::intermediate_representation::Blk>,
    ) -> Option<Self::Value> {
        let new_state = state.clone();
        Some(new_state)
    }

    /// This analysis is intraprocedural
    fn update_call(
        &self,
        _value: &Self::Value,
        _call: &crate::prelude::Term<crate::intermediate_representation::Jmp>,
        _target: &crate::analysis::graph::Node,
        _calling_convention: &Option<String>,
    ) -> Option<Self::Value> {
        None
    }

    /// This analysis is intraprocedural
    fn update_return(
        &self,
        _value: Option<&Self::Value>,
        _value_before_call: Option<&Self::Value>,
        _call_term: &crate::prelude::Term<crate::intermediate_representation::Jmp>,
        _return_term: &crate::prelude::Term<crate::intermediate_representation::Jmp>,
        _calling_convention: &Option<String>,
    ) -> Option<Self::Value> {
        None
    }

    /// This analysis is intraprocedural
    fn update_call_stub(
        &self,
        _value: &Self::Value,
        _call: &crate::prelude::Term<crate::intermediate_representation::Jmp>,
    ) -> Option<Self::Value> {
        None
    }

    fn specialize_conditional(
        &self,
        state: &Self::Value,
        condition: &crate::intermediate_representation::Expression,
        _block_before_condition: &crate::prelude::Term<crate::intermediate_representation::Blk>,
        is_true: bool,
    ) -> Option<Self::Value> {
        let mut specialized_state = state.clone();
        let mut has_taint = false;
        for input_var in condition.input_vars() {
            if self.taint.contains(input_var) {
                has_taint = true;
            }
        }
        if !has_taint {
            return Some(state.clone());
        }
        match specialized_state
            .specialize_by_expression_result(condition, Bitvector::from_u8(is_true as u8).into())
        {
            Ok(_) => Some(specialized_state),
            // State is unsatisfiable
            Err(_) => Some(state.clone()),
        }
    }
}
