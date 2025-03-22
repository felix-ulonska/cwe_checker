use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
};

use ascent::rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use itertools::Itertools;

use crate::{
    abstract_domain::{
        AbstractIdentifier, BitvectorDomain, DataDomain, RegisterDomain, SizedDomain, TryToBitvec,
    },
    intermediate_representation::{
        ir_passes::SPLIT_SYMBOL, BinOpType, Def, Expression, Program, Sub as Function, Variable,
    },
    prelude::{Bitvector, ByteSize, Term, Tid},
};

pub fn build_stack_block(program: &Program) -> StackBlockBoundaries {
    let mut boundaries = StackBlockBoundaries::new();
    let analysees: Vec<StackAnalysis> = program
        .subs
        .par_iter()
        .map(|sub| {
            let mut analysis = StackAnalysis::new(sub.1);
            analysis.analyze_block();
            analysis
        })
        .collect();
    for analysis in analysees {
        boundaries.add_analysis_result(&analysis);
    }

    boundaries
}

#[derive(Clone, Eq, Hash, PartialEq, Debug)]
pub struct StackBlock {
    pub func_tid: Tid,
    /// Relativ to $rsp. If i64.min, it is the smallest element
    pub min: i64,
    /// Relativ to $rsp. If i64.max, it is the last element
    pub max: i64,
}

#[derive(Clone, Eq, PartialEq, Default, Debug)]
pub struct StackBlockBoundaries {
    /// Maps function to stack boundaries. Stack boundaries are in reference to rsp at start of
    /// call
    stack_boundaries: HashMap<Tid, Vec<i64>>,

    pub map_register_to_stack: HashMap<Variable, StackBlock>,
}

impl StackBlockBoundaries {
    pub fn new() -> StackBlockBoundaries {
        StackBlockBoundaries {
            stack_boundaries: HashMap::new(),
            map_register_to_stack: HashMap::new(),
        }
    }

    fn add_analysis_result(&mut self, analysis_result: &StackAnalysis) {
        let boundaries_storted = analysis_result
            .boundaries
            .iter()
            .map(|boundary| {
                boundary
                    .get_if_unique_target()
                    .unwrap()
                    .1
                    .try_to_offset()
                    .unwrap()
            })
            .sorted()
            .collect_vec();
        self.stack_boundaries.insert(
            analysis_result.function.tid.clone(),
            boundaries_storted.clone(),
        );

        let mut stack_blocks = vec![];

        let mut curr_stack_block = None;

        // Build boundary blocks
        for boundary in boundaries_storted {
            if let None = curr_stack_block {
                curr_stack_block = Some(StackBlock {
                    func_tid: analysis_result.function.tid.clone(),
                    min: i64::MIN,
                    max: boundary,
                });
                continue;
            }

            if let Some(mut stack_block) = curr_stack_block {
                stack_block.max = boundary;
                stack_blocks.push(stack_block);
            }
            curr_stack_block = Some(StackBlock {
                func_tid: analysis_result.function.tid.clone(),
                min: boundary + 1,
                max: i64::MAX,
            })
        }

        if let Some(stack_block) = curr_stack_block {
            stack_blocks.push(stack_block);
        }

        for (var, state) in &analysis_result.state.register_state {
            let Some(target) = state.get_if_unique_target() else {
                continue;
            };
            let Ok(offset) = target.1.try_to_offset() else {
                continue;
            };
            for stack_block in &stack_blocks {
                if stack_block.min <= offset && stack_block.max >= offset {
                    self.map_register_to_stack
                        .insert(var.clone(), stack_block.clone());
                }
            }
        }
    }
}

impl Display for StackBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}[{}-{}]", self.func_tid, self.min, self.max)
    }
}

// TODO: add jsonCompact Trait
impl Display for StackBlockBoundaries {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (function, boundaries) in &self.stack_boundaries {
            write!(f, "Function: {}: ", function)?;
            for boundary in boundaries {
                write!(f, "{},", boundary)?;
            }
            writeln!(f, "")?;
        }
        for (reg, blk) in &self.map_register_to_stack {
            writeln!(f, "reg{}: {}", reg, blk)?;
        }

        Ok(())
    }
}

/// Analysis for one Sub.
struct StackAnalysis<'a> {
    function: &'a Term<Function>,
    state: State,
    boundaries: HashSet<BoundaryCanidate>,
}

type BoundaryCanidate = DataDomain<BitvectorDomain>;

impl<'a> StackAnalysis<'a> {
    pub fn new(function: &'a Term<Function>) -> StackAnalysis<'a> {
        return StackAnalysis {
            function,
            state: State {
                register_state: HashMap::new(),
            },
            boundaries: HashSet::new(),
        };
    }

    fn get_stack_reg(&self) -> Variable {
        let blocks = &self.function.blocks;
        for def in blocks[0].defs() {
            if let Def::Assign { var, .. } = &def.term {
                if var.name.split(SPLIT_SYMBOL).collect_vec()[0] == "RSP" {
                    return var.clone();
                }
            }
        }

        panic!("No Register Variable present in the program")
    }

    // Stolen from pointer interference
    fn eval_recursive(&self, expression: &Expression) -> BoundaryCanidate {
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
            } => BoundaryCanidate::new_top(*size),
            Subpiece {
                low_byte,
                size,
                arg,
            } => self.eval_recursive(arg).subpiece(*low_byte, *size),
            // If all inputs have the same value, we take the value, otherwise we get the top
            // symbol
            Phi(inputs) => {
                let all_values_same = inputs
                    .into_iter()
                    .map(|inp| self.state.get_register(inp))
                    .collect_vec()
                    .windows(2)
                    .all(|val| val[0] == val[1]);
                if inputs.len() == 0 || !all_values_same {
                    // TODO use correct size
                    return BoundaryCanidate::new_top(ByteSize::new(8));
                }
                self.state.get_register(&inputs[0])
            }
        }
    }

    pub fn analyze_block(&mut self) {
        self.build_canidate_set();
        self.prune_boundary_canidates();
    }

    //pub fn get_boundaries(&mut self) -> HashSet<BoundaryCanidate> {
    //    self.boundaries.clone()
    //}

    /// Prune Boundary canidates. The form of the canidates are rsp_top + c with c beeing a
    /// constant and rsp_top is the rsp at the start of the function
    /// The reference paper gives 3 cases:
    /// 1) c = 0 => Is always a boundary
    /// 2) c > 0 => Boundary
    /// 3) c < 0 => Boundary if stored in general purpose register or memory location.
    fn prune_boundary_canidates(&mut self) {
        let mut boundaries = HashMap::<Variable, BoundaryCanidate>::new();
        for (variable, data) in &self.state.register_state {
            // Stores in general purpose register, e.g. not RSP or RBP
            let offset_to_rsp = match data.get_if_unique_target() {
                Some(target) => match target.1.try_to_offset() {
                    Ok(offset) => offset,
                    _ => continue,
                },
                None => continue,
            };

            let is_case_1_or_2 = offset_to_rsp <= 0;
            let is_case_3 = variable.is_physical_register()
                && !(variable.name.contains("RSP") || variable.name.contains("RBP"));
            if is_case_1_or_2 || is_case_3 {
                boundaries.insert(variable.clone(), data.clone());
            }
        }

        // TODO inserted in memory location

        for boundary in boundaries {
            self.boundaries.insert(boundary.1);
        }
    }

    /// Builds boundary candidatas set
    fn build_canidate_set(&mut self) {
        let stack_reg = self.get_stack_reg();

        // This analysis is path unaware. It should not happen that register values pointing to the
        // stack are manipulated differently and are still base adresses
        // Pointing to stack pointer
        let abstract_stack_pointer = AbstractIdentifier::new(
            self.function.blocks[0].tid.clone(),
            crate::abstract_domain::AbstractLocation::from_stack_position(
                &stack_reg,
                0,
                ByteSize::new(8),
            ),
        );
        let init_rsp = BoundaryCanidate::from_target(
            abstract_stack_pointer,
            BitvectorDomain::Value(Bitvector::from_u64(0)),
        );
        self.state.change_register(stack_reg, init_rsp);

        // Fixpoint recursion: Loop over all defs until setteled. Here can be optimization in order
        // of execution and what parts gets re executed.
        let mut changed = false;
        for _i in 0..10 {
            changed = self.analysis_pass();
            if !changed {
                break;
            }
        }
        // TODO transmit error
        if changed {
            println!("Loop did not settle");
        }
    }

    /// Iterate over all defs in project and search for usages
    fn analysis_pass(&mut self) -> bool {
        let mut changed = false;
        for blk in &self.function.blocks {
            for def in blk.defs() {
                match def {
                    Term {
                        tid: _,
                        term: Def::Assign { var, value },
                    } => {
                        let new_val = self.eval_recursive(value);
                        if !new_val.get_relative_values().is_empty() {
                            changed |= self.state.change_register(var.clone(), new_val);
                        }
                    }
                    // Stack adress is saved to memory (case 3)
                    // Might want to check which mem region it is saved to
                    Term {
                        tid: _,
                        term: Def::Store { address, value },
                    } => {
                        let is_stack_addr = !self
                            .eval_recursive(address)
                            .get_relative_values()
                            .is_empty();
                        if !is_stack_addr {
                            let new_val = self.eval_recursive(value);
                            if !new_val.get_relative_values().is_empty() {
                                self.boundaries.insert(new_val);
                            }
                        }
                    }
                    _ => (),
                }
            }
        }

        changed
    }
}

#[derive(Eq, PartialEq, Clone)]
struct State {
    // TODO specific for architecture?
    register_state: HashMap<Variable, BoundaryCanidate>,
}

impl State {
    fn get_register(&self, variable: &Variable) -> BoundaryCanidate {
        self.register_state
            .get(variable)
            .unwrap_or(&BoundaryCanidate::new_top(variable.size))
            .clone()
    }

    /// Returns true, if something changed
    fn change_register(&mut self, variable: Variable, value: BoundaryCanidate) -> bool {
        match self.register_state.insert(variable, value.clone()) {
            Some(old_data) => old_data != value,
            None => true,
        }
    }
}

impl Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (var, data) in &self.register_state {
            write!(f, "{}=", var)?;
            match data.get_if_unique_target() {
                Some((_target, value)) => write!(f, "RSP + {}", value.to_string())?,
                None => write!(f, "unknown")?,
            }
            write!(f, "\n")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use crate::{
        defs, expr,
        intermediate_representation::{self, Blk, Project},
    };
    use intermediate_representation::*;

    use super::StackAnalysis;

    fn build_prog_with_block(defs: Vec<Term<Def>>) -> Project {
        let mut project = Project::mock_x64();
        let mut blk1 = Blk::default();
        blk1.defs = defs;
        blk1.add_jumps(vec![Term {
            term: Jmp::Return(expr!["0x00:8"]),
            tid: Tid::new("jmp"),
        }]);
        let blk1 = Term {
            tid: Tid::new("blk1"),
            term: blk1,
        };
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
            "term_1: RSP__1:8 = phi()",
            "term_1_1: RAX__1:8 = phi()",
            "term_2: RSP__2:8 = RSP__1:8 + 0x08:8",
            "term_3: RAX__1:8 = RSP__2:8 + 0x08:8"
        ]);
        let mut stack_analysis =
            StackAnalysis::new(&project.program.term.subs.first_key_value().unwrap().1);
        stack_analysis.analyze_block();
        assert!(stack_analysis.state.register_state.len() == 3);
        assert!(stack_analysis.state.register_state.len() == 3);
        println!("{}", stack_analysis.state);
    }
}
