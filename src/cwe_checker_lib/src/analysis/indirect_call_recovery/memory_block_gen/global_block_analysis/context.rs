use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Display,
    sync::Arc,
};

use apint::ApInt;
use serde::{Deserialize, Serialize};

use crate::{
    abstract_domain::{
        AbstractDomain, AbstractIdentifier, AbstractLocation, DataDomain, DomainMap,
        IntervalDomain, MergeTopStrategy, RegisterDomain, SizedDomain, TryToBitvec, TryToInterval,
    },
    analysis::{
        forward_intraprocdural_fixpoint::Context, graph::intraprocedural_cfg::IntraproceduralCfg,
    },
    intermediate_representation::{BinOpType, Def, Expression, Program, Sub, Variable},
    prelude::{Bitvector, ByteSize, Term, Tid},
};

pub type ValueDomain = IntervalDomain;

/// The abstract domain type for representing register values.
pub type Data = DataDomain<ValueDomain>;

// A lot of the following is taken from the pointer interference, however this only includes the
// necassary to determine intereger values.

/// Contains all information known about the state of a program at a specific point of time.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct State {
    /// Maps a register variable to the data known about its content.
    /// A variable not contained in the map has value `Data::Top(..)`, i.e. nothing is known about its content.
    register: DomainMap<Variable, Data, MergeTopStrategy>,
    /// A list of constants that are assumed to be addresses of global variables accessed by this function.
    /// Used to replace constants by relative values pointing to the global memory object.
    known_global_addresses: Arc<BTreeSet<u64>>,
    /// The abstract identifier of the current stack frame.
    /// It points to the base of the stack frame, i.e. only negative offsets point into the current stack frame.
    pub stack_id: AbstractIdentifier,
}

impl State {
    pub fn new(
        stack_register: &Variable,
        function_tid: Tid,
        global_addresses: BTreeSet<u64>,
    ) -> State {
        let stack_id = AbstractIdentifier::new(
            function_tid,
            AbstractLocation::from_var(stack_register).unwrap(),
        );
        let mut register = DomainMap::from(BTreeMap::new());
        register.insert(
            stack_register.clone(),
            Data::from_target(
                stack_id.clone(),
                Bitvector::zero(apint::BitWidth::from(stack_register.size)).into(),
            ),
        );
        State {
            register,
            //memory: AbstractObjectList::from_stack_id(stack_id.clone(), stack_register.size),
            stack_id,
            known_global_addresses: Arc::new(global_addresses),
        }
    }

    /// Get the value of a register or Top() if no value is known.
    pub fn get_register(&self, variable: &Variable) -> Data {
        if let Some(data) = self.register.get(variable) {
            data.clone()
        } else {
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
        println!(
            "set register {} to {:#?} from {}",
            target,
            self.eval(expression),
            expression
        );
        self.set_register(target, self.eval(expression))
    }

    /// Evaluate the value of an expression in the current state.
    pub fn eval(&self, expression: &Expression) -> Data {
        let result = self.eval_recursive(expression);
        self.replace_if_global_pointer(result)
    }

    /// If the input value is a constant that is also the address of a global variable known to the function
    /// then replace it with a value relative to the global memory ID of the state.
    fn replace_if_global_pointer(&self, mut value: Data) -> Data {
        if let Ok(constant) = value.try_to_offset() {
            //if self.known_global_addresses.contains(&(constant as u64)) {
            //    // The result is a constant that denotes a pointer to global writeable memory.
            //    // Thus we replace it with a value relative the global memory ID.
            //    value = Data::from_target(
            //        self.get_global_mem_id(),
            //        value.try_to_interval().unwrap().into(),
            //    );
            //}
        }
        value
    }

    /// Recursively evaluate the value of an expression in the current state.
    /// Should only be called by [`State::eval`].
    fn eval_recursive(&self, expression: &Expression) -> Data {
        use Expression::*;
        println!("Expr: {}", expression);
        match expression {
            Var(variable) => self.get_register(variable),
            Const(bitvector) => bitvector.clone().into(),
            BinOp { op, lhs, rhs } => {
                if *op == BinOpType::IntXOr && lhs == rhs {
                    // the result of `x XOR x` is always zero.
                    return Bitvector::zero(apint::BitWidth::from(lhs.bytesize())).into();
                }
                let (left, right) = (self.eval_recursive(lhs), self.eval_recursive(rhs));
                left.bin_op(*op, &right)
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
            } => self.eval_recursive(arg).subpiece(*low_byte, *size),
            Phi(inputs) => inputs
                .iter()
                // Ensure that values are set, otherwise not yet inited value would inject a top
                // value
                .filter(|input| self.register.get(input).is_some())
                .fold(Data::new_empty(ByteSize::new(8)), |data, val| {
                    println!(
                        "phi function: {:#?}, {}, adding {:#?}",
                        data,
                        val,
                        self.get_register(val)
                    );
                    data.clone().merge(&self.get_register(val))
                }),
        }
    }
}

impl Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (reg, value) in self.register.iter() {
            //println!("Intervall {:#?} ", value);
            let Some(value) = value.get_absolute_value() else {
                write!(f, "{}: [-]", reg.name)?;
                continue;
            };
            write!(f, "{}:{}", reg.name, value)?;
        }
        Ok(())
    }
}

impl AbstractDomain for State {
    /// Merge two states
    fn merge(&self, other: &Self) -> Self {
        //let merged_memory_objects = self.memory.merge(&other.memory);
        State {
            register: self.register.merge(&other.register),
            known_global_addresses: self.known_global_addresses.clone(),
            stack_id: self.stack_id.clone(),
        }
    }

    /// A state has no *Top* element
    fn is_top(&self) -> bool {
        false
    }
}

pub struct AnalysisContext<'a> {
    program: &'a Program,
    sub: &'a Term<Sub>,
    cfg: IntraproceduralCfg<'a>,
}

impl<'a> AnalysisContext<'a> {
    pub fn new(program: &'a Program, sub: &'a Term<Sub>) -> AnalysisContext<'a> {
        let cfg = IntraproceduralCfg::new(program, sub);
        AnalysisContext { program, sub, cfg }
    }
}

impl<'a> Context<'a> for AnalysisContext<'a> {
    type Value = State;

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
            Def::Store { address, value } => {
                //self.log_debug(
                //    new_state.handle_store(address, value, &self.project.runtime_memory_image),
                //    Some(&def.tid),
                //);
                //Some(new_state)
                Some(new_state)
            }
            Def::Assign { var, value } => {
                new_state.handle_register_assign(var, value);
                Some(new_state)
            }
            Def::Load { var, address } => Some(new_state),
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
        value: &Self::Value,
        _call: &crate::prelude::Term<crate::intermediate_representation::Jmp>,
    ) -> Option<Self::Value> {
        None
    }

    fn specialize_conditional(
        &self,
        state: &Self::Value,
        condition: &crate::intermediate_representation::Expression,
        block_before_condition: &crate::prelude::Term<crate::intermediate_representation::Blk>,
        is_true: bool,
    ) -> Option<Self::Value> {
        let mut specialized_state = state.clone();
        match specialized_state
            .specialize_by_expression_result(condition, Bitvector::from_u8(is_true as u8).into())
        {
            Ok(_) => Some(specialized_state),
            // State is unsatisfiable
            Err(_) => None,
        }
    }
}
