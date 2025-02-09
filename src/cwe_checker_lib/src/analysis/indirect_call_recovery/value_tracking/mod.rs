use std::{
    collections::{HashMap, HashSet},
    rc::Rc,
    sync::Arc,
};

use crate::{
    intermediate_representation::{Def, Expression, Jmp, Program, Variable},
    prelude::{Bitvector, ByteSize, Term, Tid},
};

use ascent::ascent;
use itertools::Itertools;

use super::{
    function_taken::AtFunction,
    memory_block_gen::{
        global_block::Interval, heap_block::HeapBlock, stack_block::StackBlock, BlockMemoryModel,
    },
};

type Symbol = Rc<String>;

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct Read(Symbol);

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct Write(Symbol);

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct Jump(Symbol);

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum Instr {
    Read(Read),
    Write(Write),
    Jump(Jump),
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct Mblk(Symbol);

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct Sblk(Arc<StackBlock>);

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct Hblk(Arc<HeapBlock>);

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct Gblk(Interval);

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct Reg {
    var: Arc<Variable>,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum Mloc {
    Gblk(Gblk),
    Mblk(Mblk),
    Sblk(Sblk),
    Hblk(Hblk),
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum Loc {
    Mloc(Mloc),
    Reg(Reg),
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum Exp {
    Empty,
    Reg(Reg),
    Mloc(Mloc),
    Deref(Reg),
    RefMLoc(Mloc),
    RefFunc(AtFunction),
    Union(Arc<Exp>, Arc<Exp>),
}

impl Exp {
    fn to_iter(&self) -> Vec<Exp> {
        if let Exp::Union(exp1, exp2) = self {
            [exp1.to_iter(), exp2.to_iter()].concat()
        } else {
            vec![self.clone()]
        }
    }
}

impl From<Exp> for Loc {
    fn from(value: Exp) -> Self {
        match value {
            Exp::Reg(reg) => Loc::Reg(reg),
            Exp::Mloc(mloc) => Loc::Mloc(mloc),
            _ => todo!(),
        }
    }
}

impl From<Reg> for Loc {
    fn from(value: Reg) -> Self {
        Loc::Reg(value)
    }
}
impl From<&Reg> for Loc {
    fn from(value: &Reg) -> Self {
        Loc::Reg(value.clone())
    }
}
impl From<Mloc> for Loc {
    fn from(value: Mloc) -> Self {
        Loc::Mloc(value)
    }
}
impl From<&Mloc> for Loc {
    fn from(value: &Mloc) -> Self {
        Loc::Mloc(value.clone())
    }
}

macro_rules! aloc_val_with_vset {
    ($vset_macro:ident) => {
        aloc_val(ireg.into(), val) <--
            assign_reg(ireg, union),
            if let Exp::Union(exp1, exp2) = union,
            $vset_macro!(val, union);
    };
}

ascent! {
    relation assign_reg(Reg, Exp);
    relation assign_mloc(Mloc, Exp);
    relation assing_deref_reg(Reg, Exp);
    relation undeterministic_assign(Reg, Mloc, Exp);
    relation phi(Reg, Reg);

    relation assign(Loc, Exp);

    // Assign is a helper relation: Models if an exp can be assigned to an mloc
    // assign_reg
    assign(reg.into(), exp) <-- assign_reg(reg, exp);
    // assign_mloc: change for rules
    assign(mloc.into(), exp) <-- assign_mloc(mloc, exp);
    assign(mloc.into(), exp) <-- assing_deref_reg(reg, exp), aloc_val(Loc::Reg(reg.clone()), ?Exp::RefMLoc(mloc));

    relation aloc_val(Loc, Exp);

    relation vset(Exp, Exp);

    macro vset_mloc_func($v: ident, $exp: ident) {
        for $v in $exp.to_iter(),
        if let Exp::RefFunc(_) | Exp::RefMLoc(_) = $v,
    }

    macro vset_ireg($v: ident, $exp: ident) {
        for exp in $exp.to_iter(),
        if let Exp::Reg(reg) = exp,
        aloc_val(Loc::Reg(reg), $v)
    }

    macro vset_mloc($v: ident, $exp: ident) {
        for exp in $exp.to_iter(),
        if let Exp::Mloc(mloc) = exp,
        aloc_val(Loc::Mloc(mloc), $v)
    }

    macro vset_deref_ireg($v: ident, $exp: ident) {
        for exp in $exp.to_iter(),
        if let Exp::Deref(reg) = exp,
        aloc_val(Loc::Reg(reg), ?Exp::RefMLoc(mloc)),
        aloc_val(Loc::Mloc(mloc.clone()), $v)
    }

    // AddrMloc and AddrFunc
    aloc_val(loc, mloc) <-- assign(loc, ?mloc@(Exp::Mloc(_) | Exp::RefFunc(_)));
    // IReg and Mloc
    aloc_val(loc, val) <-- assign(loc, exp), aloc_val(loc, val);
    // DIreg
    aloc_val(loc, val) <--
        assign(loc, ?Exp::Deref(src_reg)),
        aloc_val(Loc::Reg(src_reg.clone()), ?Exp::RefMLoc(mloc)),
        aloc_val(Loc::Mloc(mloc.clone()), val);

    aloc_val(loc, v) <--
        assign(loc, union),
        if let Exp::Union(exp1, exp2) = union,
        vset_mloc_func!(v, union);

    // Vset(ireg)
    aloc_val(loc, v) <--
        assign(loc, union),
        if let Exp::Union(exp1, exp2) = union,
        vset_ireg!(v, union);

    // Vset(mloc)
    aloc_val(loc, v) <--
        assign(loc, union),
        if let Exp::Union(exp1, exp2) = union,
        vset_mloc!(v, union);

    // Vset(*ireg)
    aloc_val(loc, v) <--
        assign(loc, union),
        if let Exp::Union(exp1, exp2) = union,
        vset_deref_ireg!(v, union);

    // UpdMloc
    // Vset(&mloc) and Vset(&func)
    aloc_val(mloc.into(), v) <--
        assing_deref_reg(ireg, exp),
        aloc_val(Loc::Reg(ireg.clone()), ?Exp::RefMLoc(mloc)),
        vset_mloc_func!(v, exp);

    // Vset(ireg)
    aloc_val(Loc::Mloc(mloc.clone()), val) <--
        assing_deref_reg(ireg, exp),
        aloc_val(Loc::Reg(ireg.clone()), ?Exp::RefMLoc(mloc)),
        vset_ireg!(val, exp);

    // Vset(mloc)
    aloc_val(Loc::Mloc(mloc.clone()), val) <--
        assing_deref_reg(ireg, exp),
        aloc_val(Loc::Reg(ireg.clone()), ?Exp::RefMLoc(mloc)),
        vset_mloc!(val, exp);

    // Vset(*ireg)
    aloc_val(Loc::Mloc(mloc.clone()), val) <--
        assing_deref_reg(ireg, exp),
        aloc_val(Loc::Reg(ireg.clone()), ?Exp::RefMLoc(mloc)),
        vset_deref_ireg!(val, exp);

    // Phi
    aloc_val(Loc::Reg(ireg.clone()), val) <-- phi(ireg, sreg), aloc_val(Loc::Reg(sreg.clone()), val);
}

/// Converts an Vec<Variable> to Tree like Exp expressions where the expressions is a union of all
/// possible vars
fn build_union_of_vars(vars: &Vec<&Variable>) -> Exp {
    let mut exps = vars
        .into_iter()
        .map(|var| {
            Exp::Reg(Reg {
                var: Arc::new(var.clone().clone()),
            })
        })
        .collect_vec();

    // Terminates as each iter, 2 pops and 1 add.
    while exps.len() > 1 {
        let exp_first = exps.pop().unwrap();
        let exp_second = exps.pop().unwrap();
        exps.push(Exp::Union(Arc::new(exp_first), Arc::new(exp_second)));
    }

    exps.pop()
        .expect("The function should not be called with no input var")
}

pub struct ValueTracking<'a> {
    program: &'a Program,
    block_memory: &'a BlockMemoryModel,
    at_functions: &'a HashSet<AtFunction>,
    at_functions_by_addr: HashMap<u64, AtFunction>,
}

impl ValueTracking<'_> {
    /// Parse a const addr to exp
    fn parse_const(&self, bitvector: &Bitvector) -> Exp {
        let Ok(val) = bitvector.try_to_u64() else {
            return Exp::Empty;
        };

        if let Some(at_function) = self.at_functions_by_addr.get(&val) {
            return Exp::RefFunc(at_function.clone());
        }

        if let Some(interval) = self.block_memory.global.get_interval(val as i64) {
            return Exp::Mloc(Mloc::Gblk(Gblk(interval.clone())));
        }

        Exp::Empty
    }

    fn expression_to_value_tracking(&self, exp: &Expression) -> Exp {
        match exp {
            Expression::Var(var) => Exp::Reg(Reg {
                var: var.clone().into(),
            }),
            // TODO add infer for function pointer and global pointer
            Expression::Const(bitvector) => self.parse_const(bitvector),
            Expression::BinOp { lhs, rhs, .. } => Exp::Union(
                Arc::new(self.expression_to_value_tracking(&*lhs)),
                Arc::new(self.expression_to_value_tracking(&*rhs)),
            ),
            Expression::UnOp { arg, .. }
            | Expression::Cast { arg, .. }
            | Expression::Subpiece { arg, .. } => self.expression_to_value_tracking(&*arg),
            Expression::Unknown { .. } => panic!(),
            Expression::Phi(vars) => build_union_of_vars(&vars.iter().collect()),
        }
    }

    pub fn new<'a>(
        program: &'a Program,
        block_memory: &'a BlockMemoryModel,
        at_functions: &'a HashSet<AtFunction>,
    ) -> ValueTracking<'a> {
        let mut at_functions_by_addr = HashMap::new();
        for func in at_functions {
            at_functions_by_addr.insert(func.first_instruction, func.clone());
        }

        ValueTracking {
            program,
            block_memory,
            at_functions,
            at_functions_by_addr,
        }
    }

    // We need to mantain a mapping of tid to int ids. We need to have copabale things, and
    pub fn run_value_tracking(&self) {
        let mut prog = AscentProgram::default();

        prog.assign_reg = vec![];
        prog.assign_mloc = vec![];
        prog.assing_deref_reg = vec![];
        prog.undeterministic_assign = vec![];

        for blk in self.program.blocks() {
            for def in blk.defs() {
                let _tid = def.tid.clone();
                match &def.term {
                    // AssignReg
                    Def::Load { var, address } => {
                        if let Some(interval) =
                            self.block_memory.global.get_interval_of_def(def.clone())
                        {
                            prog.assign_reg.push((
                                Reg {
                                    var: Arc::new(var.clone()),
                                },
                                Exp::Mloc(Mloc::Gblk(Gblk(interval.clone()))),
                            ));
                            continue;
                        }

                        let inputs_vars = address.input_vars();
                        if inputs_vars.len() == 1 {
                            prog.assign_reg.push((
                                Reg {
                                    var: Arc::new(var.clone()),
                                },
                                Exp::Reg(Reg {
                                    var: Arc::new(inputs_vars[0].clone()),
                                }),
                            ));
                        } else if inputs_vars.len() > 1 {
                            // Build temp variable which includes all possible inputs
                            let temp_var = Arc::new(Variable {
                                name: format!("tempSrcAddrFor{}", var.name),
                                size: var.size,
                                is_temp: true,
                            });
                            prog.assign_reg.push((
                                Reg {
                                    var: temp_var.clone(),
                                },
                                build_union_of_vars(&inputs_vars),
                            ));
                            prog.assign_reg.push((
                                Reg {
                                    var: Arc::new(var.clone()),
                                },
                                Exp::Reg(Reg { var: temp_var }),
                            ));
                        }
                    }
                    // AssignMloc
                    Def::Store { address, value } => {
                        if let Some(interval) =
                            self.block_memory.global.get_interval_of_def(def.clone())
                        {
                            prog.assign_mloc.push((
                                Mloc::Gblk(Gblk(interval.clone())),
                                self.expression_to_value_tracking(&value),
                            ));
                            continue;
                        }

                        // TODO: refactor code dupl
                        let input_vars = address.input_vars();
                        if input_vars.len() == 1 {
                            prog.assing_deref_reg.push((
                                Reg {
                                    var: Arc::new(input_vars[0].clone()),
                                },
                                Exp::Reg(Reg {
                                    var: Arc::new(input_vars[0].clone()),
                                }),
                            ));
                        } else if input_vars.len() > 1 {
                            // Build temp variable which includes all possible inputs
                            let temp_var = Arc::new(Variable {
                                name: format!("tempSrcAddrFor{}", def.tid),
                                // TODO
                                size: ByteSize::new(8), // var.size,
                                is_temp: true,
                            });
                            prog.assign_reg.push((
                                Reg {
                                    var: temp_var.clone(),
                                },
                                build_union_of_vars(&input_vars),
                            ));
                            prog.assing_deref_reg.push((
                                Reg {
                                    var: temp_var.clone(),
                                },
                                self.expression_to_value_tracking(&value),
                            ));
                        }
                    }
                    // AssignReg
                    Def::Assign { var, value } => prog.assign_reg.push((
                        Reg {
                            var: Arc::new(var.clone()),
                        },
                        self.expression_to_value_tracking(&value),
                    )),
                }
            }
        }

        // inject heap values:
        //      Orignal: target_reg <- &heap
        // Represent as:
        //      Add temp_var <- &Mloc(heap)
        //      Add phi(target_reg, temp_var)
        for (heap_target_var, heap_blk) in &self.block_memory.heap.register_with_heap {
            let temp_var = Variable {
                name: format!("temp_heap_{}", heap_blk.id),
                is_temp: true,
                size: heap_target_var.size,
            };
            prog.assign_reg.push((
                Reg {
                    var: Arc::new(temp_var.clone()),
                },
                Exp::RefMLoc(Mloc::Hblk(Hblk(Arc::new(heap_blk.clone())))),
            ));
            prog.phi.push((
                Reg {
                    var: Arc::new(heap_target_var.clone()),
                },
                Reg {
                    var: Arc::new(temp_var.clone()),
                },
            ))
        }

        // similar to heap, do stack
        //      Orignal: target_reg <- &heap
        // Represent as:
        //      Add temp_var <- &Mloc(heap)
        //      Add phi(target_reg, temp_var)
        for (stack_target_var, stack_blk) in &self.block_memory.stack.map_register_to_stack {
            let temp_var = Variable {
                name: format!(
                    "temp_stack_{}_{}_{}",
                    stack_blk.func_tid, stack_blk.min, stack_blk.max
                ),
                is_temp: true,
                size: stack_target_var.size,
            };
            prog.assign_reg.push((
                Reg {
                    var: Arc::new(temp_var.clone()),
                },
                Exp::RefMLoc(Mloc::Sblk(Sblk(Arc::new(stack_blk.clone())))),
            ));
            prog.phi.push((
                Reg {
                    var: Arc::new(stack_target_var.clone()),
                },
                Reg {
                    var: Arc::new(temp_var.clone()),
                },
            ))
        }

        prog.run();

        let mut map = HashMap::<Variable, Vec<Tid>>::new();
        for (loc, expr) in prog.aloc_val {
            if let Exp::RefFunc(func) = expr {
                if let Loc::Reg(reg) = loc {
                    let vec = map
                        .get(&reg.var)
                    //map.insert(reg.var.clone(), func);
                }
            }
        }

        for icall in self.program.jmps().filter(|jmp| jmp.is_indirect_call()) {
            if let Term {
                term: Jmp::CallInd { target, return_ },
                tid,
            } = &icall
            {
                for input_var in target.input_vars() {}
            }
        }
    }
}
