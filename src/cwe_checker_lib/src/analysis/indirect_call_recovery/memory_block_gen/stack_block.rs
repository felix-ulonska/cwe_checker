use std::{collections::HashMap, fmt::Display};

use itertools::Itertools;

use crate::{abstract_domain::{AbstractIdentifier, BitvectorDomain, DataDomain, RegisterDomain, SizedDomain}, analysis::graph::intraprocedural_cfg::IntraproceduralCfg, intermediate_representation::{BinOpType, Def, Expression, Program, Sub as Function, Variable}, prelude::{Bitvector, ByteSize, Term}};

/// Analysis for one Sub.
pub struct StackAnalysis<'a> {
    program: &'a Program,
    function: &'a Term<Function>,
    cfg: IntraproceduralCfg<'a>,
    state: State,
}

type Data = DataDomain::<BitvectorDomain>;

impl<'a> StackAnalysis<'a> {
    fn new(program: &'a Program, function: &'a Term<Function>) -> StackAnalysis<'a> {
        return StackAnalysis {
            program,
            function,
            cfg: IntraproceduralCfg::new(program, function),
            state: State { register_state: HashMap::new() }
        }
    }

    fn get_stack_reg(&self) -> Variable {
        let blocks = &self.function.blocks;
        for def in blocks[0].defs() {
            if let Def::Assign{var, ..} = &def.term {
                if var.name.split("_").collect_vec()[0] == "RSP" {
                    return var.clone();
                }
            }
        }

        panic!("No Register Variable present in the program")
    }

    // Stolen from pointer interference
    fn eval_recursive(&self, expression: &Expression) -> Data {
        use Expression::*;
        match expression {
            Var(variable) => self.state.get_register(variable),
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
            Phi(input) => match input.as_slice() {
                [input] => self.state.get_register(input),
                _ => Data::new_top(ByteSize::new(0))
            }
        }
    }

    pub fn analyze_block(&mut self) {
        self.gen_value_set_for_block()
    }

    fn gen_value_set_for_block(&mut self) {
        let stack_reg = self.get_stack_reg();

        // This analysis is path unaware. It should not happen that register values pointing to the
        // stack are manipulated differently and are still base adresses 
        // Pointing to stack pointer
        let abstract_stack_pointer = AbstractIdentifier::new(
            self.function.blocks[0].tid.clone(),
            crate::abstract_domain::AbstractLocation::from_stack_position(&stack_reg, 0, ByteSize::new(0))
        );
        let init_rsp = Data::from_target(abstract_stack_pointer, BitvectorDomain::Value(Bitvector::from_u64(0)));
        self.state.add_register(stack_reg, init_rsp);

        for blk in &self.function.blocks {
            for def in blk.defs() {
                if let Term { tid: _, term: Def::Assign { var, value } } = def {
                    let new_val = self.eval_recursive(value);
                    if !new_val.get_relative_values().is_empty() {
                        self.state.add_register(var.clone(), new_val);
                    }
                }
            }
        }
    }
}


#[derive(Eq, PartialEq, Clone)]
struct State {
    // TODO specific for architecture?
    register_state: HashMap<Variable, Data>
}

impl State {
    fn get_register(&self, variable: &Variable) -> Data {
        self.register_state.get(variable).unwrap_or(&Data::new_top(ByteSize::new(0))).clone()
    }

    fn add_register(&mut self, variable: Variable, value: Data) {
        self.register_state.insert(variable, value);
    }
}

impl Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (var, data) in &self.register_state {
            write!(f, "{}=", var)?;
            match data.get_if_unique_target() {
                Some((_target, value)) => write!(f, "RSP + {}", value.to_string())?,
                None => write!(f, "unknown")?
            }
            write!(f, "\n")?
        }
        write!(f, "\n")
    }
}

pub fn build_stack_block(program: &Program) {
    for sub in &program.subs {
        let mut stack_analysis = StackAnalysis::new(program, &sub.1);
        stack_analysis.analyze_block();
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use crate::{defs, expr, intermediate_representation::{self, Blk, Project}};
    use intermediate_representation::*;

    use super::{build_stack_block, StackAnalysis};

    fn build_prog_with_block(defs: Vec<Term<Def>>) -> Project {
        let mut project = Project::mock_x64();
        let mut blk1 = Blk::default();
        blk1.defs = defs;
        blk1.add_jumps(vec![Term {
            term: Jmp::Return(expr!["0x00:8"]),
            tid: Tid::new("jmp")
        }]);
        let blk1 = Term { tid: Tid::new("blk1"), term: blk1 };
        let sub1 = Term {
            tid: Tid::new("sub1"),
            term: Sub::new::<_, &str>("sub1", vec![blk1], None),
        };
        let program = Term {
            tid: Tid::new("program"),
            term: Program {
                subs: BTreeMap::from_iter([(sub1.tid.clone(), sub1)]),
                extern_symbols: BTreeMap::new(),
                entry_points: BTreeSet::new(),
                address_base_offset: 0,
            },
        };
        project.program = program;

        project
    }

    #[test]
    fn test_stack_analysis() {
        let project = build_prog_with_block(defs![
            "term_1: RSP_1:8 = phi()",
            "term_2: RSP_2:8 = RSP_1:8 + 0x08:8"
        ]);
        build_stack_block(&project.program);
        let mut stack_analysis = StackAnalysis::new(&project.program.term, &project.program.term.subs.first_key_value().unwrap().1);
        stack_analysis.analyze_block();
        assert!(stack_analysis.state.register_state.len() == 2);
        println!("{}", stack_analysis.state);
    }
}
