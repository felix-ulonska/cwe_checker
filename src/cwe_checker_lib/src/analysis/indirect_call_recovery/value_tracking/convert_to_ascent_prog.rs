use itertools::Itertools;

use crate::analysis::indirect_call_recovery::{
    function_taken::AtFunction,
    memory_block_gen::BlockMemoryModel,
    value_tracking::{build_union_of_vars, AscentProgram, Blk, Hblk, Loc, Reg},
};
use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
    sync::Arc,
};

use crate::{
    intermediate_representation::{
        ir_passes::VarsAtEndOfBlock, Def, Expression, Jmp, Program, Variable,
    },
    prelude::{Bitvector, ByteSize, Term, Tid},
};

use super::{Exp, Gblk, Mloc, Sblk};

pub struct ValueTracking<'a> {
    program: &'a Program,
    block_memory: &'a BlockMemoryModel,
    at_functions: &'a HashSet<AtFunction>,
    at_functions_by_addr: HashMap<u64, AtFunction>,
    active_var_at_end_of_block: &'a VarsAtEndOfBlock,
    ascent_prog: AscentProgram,
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
        active_var_at_end_of_block: &'a VarsAtEndOfBlock,
    ) -> ValueTracking<'a> {
        let mut at_functions_by_addr = HashMap::new();
        for func in at_functions {
            at_functions_by_addr.insert(func.first_instruction, func.clone());
        }

        let prog = AscentProgram::default();
        ValueTracking {
            program,
            block_memory,
            at_functions,
            at_functions_by_addr,
            active_var_at_end_of_block,
            ascent_prog: prog,
        }
    }

    fn convert_def_to_ascent(&mut self) {
        for blk in self.program.blocks() {
            for def in blk.defs() {
                let _tid = def.tid.clone();
                match &def.term {
                    // AssignReg
                    Def::Load { var, address } => {
                        if let Some(interval) =
                            self.block_memory.global.get_interval_of_def(def.clone())
                        {
                            let var = Arc::new(var.clone());
                            self.ascent_prog.assign_reg.push((
                                Reg { var: var.clone() },
                                Exp::Mloc(Mloc::Gblk(Gblk(interval.clone()))),
                            ));
                            self.ascent_prog
                                .reg_to_block
                                .push((Reg { var: var.clone() }, Blk(Arc::new(blk.tid.clone()))));
                            continue;
                        }

                        let inputs_vars = address.input_vars();
                        if inputs_vars.len() == 1 {
                            self.ascent_prog.assign_reg.push((
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
                            self.ascent_prog.assign_reg.push((
                                Reg {
                                    var: temp_var.clone(),
                                },
                                build_union_of_vars(&inputs_vars),
                            ));
                            self.ascent_prog.assign_reg.push((
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
                            self.ascent_prog.assign_mloc.push((
                                Mloc::Gblk(Gblk(interval.clone())),
                                self.expression_to_value_tracking(&value),
                            ));
                            continue;
                        }

                        // TODO: refactor code dupl
                        let input_vars = address.input_vars();
                        if input_vars.len() == 1 {
                            self.ascent_prog.assing_deref_reg.push((
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
                            self.ascent_prog.assign_reg.push((
                                Reg {
                                    var: temp_var.clone(),
                                },
                                build_union_of_vars(&input_vars),
                            ));
                            self.ascent_prog.assing_deref_reg.push((
                                Reg {
                                    var: temp_var.clone(),
                                },
                                self.expression_to_value_tracking(&value),
                            ));
                        }
                    }
                    // AssignReg
                    Def::Assign { var, value } => {
                        if let Expression::Phi(vars) = value {
                            for source_var in vars {
                                self.ascent_prog.phi.push((
                                    Reg {
                                        var: Arc::new(var.clone()),
                                    },
                                    Reg {
                                        var: source_var.clone().into(),
                                    },
                                    Blk(blk.tid.clone().into()),
                                ))
                            }
                        } else {
                            self.ascent_prog.reg_to_block.push((
                                Reg {
                                    var: Arc::new(var.clone()),
                                },
                                Blk(Arc::new(blk.tid.clone())),
                            ));
                            self.ascent_prog.assign_reg.push((
                                Reg {
                                    var: Arc::new(var.clone()),
                                },
                                self.expression_to_value_tracking(&value),
                            ))
                        }
                    }
                }
            }
        }
    }

    fn add_used_func_call(&mut self) {
        for blk in self.program.blocks() {
            for jmp in blk.jmps() {
                if !jmp.is_indirect_call() {
                    continue;
                }

                if let Jmp::CallInd { target, .. } = &jmp.term {
                    for input_var in target.input_vars() {
                        self.ascent_prog.used_func_call.push((
                            Reg {
                                var: Arc::new(input_var.clone()),
                            },
                            Blk(Arc::new(blk.tid.clone())),
                        ));
                    }
                }
            }
        }
    }

    fn add_reg_to_block(&mut self) {
        for (blk, active_vars) in self.active_var_at_end_of_block {
            for var in active_vars {
                self.ascent_prog.reg_to_block.push((
                    Reg {
                        var: Arc::new(var.clone()),
                    },
                    Blk(blk.clone().into()),
                ))
            }
        }
    }

    fn add_atfunc_to_block(&mut self) {
        for atfunction in self.at_functions {
            self.ascent_prog
                .atfunc_to_block
                .push((atfunction.clone(), Blk(atfunction.tid.clone().into())));
        }
    }

    fn add_heap_aloc_val(&mut self) {
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
            self.ascent_prog.aloc_val.push((
                Loc::Reg(Reg {
                    var: Arc::new(temp_var.clone()),
                }),
                Exp::RefMLoc(Mloc::Hblk(Hblk(Arc::new(heap_blk.clone())))),
            ));
        }
    }

    fn add_stack_aloc_val(&mut self) {
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
            self.ascent_prog.assign_reg.push((
                Reg {
                    var: Arc::new(temp_var.clone()),
                },
                Exp::RefMLoc(Mloc::Sblk(Sblk(Arc::new(stack_blk.clone())))),
            ));
            self.ascent_prog.phi.push((
                Reg {
                    var: Arc::new(stack_target_var.clone()),
                },
                Reg {
                    var: Arc::new(temp_var.clone()),
                },
                Blk(Arc::new(stack_blk.func_tid.clone())),
            ));
        }
    }

    fn convert(&mut self) {
        let prog = &mut self.ascent_prog;
        prog.assign_reg = vec![];
        prog.assign_mloc = vec![];
        prog.assing_deref_reg = vec![];
        prog.undeterministic_assign = vec![];

        self.convert_def_to_ascent();
        self.add_reg_to_block();
        self.add_atfunc_to_block();
        self.add_stack_aloc_val();
        self.add_used_func_call();
        self.add_heap_aloc_val();
    }

    // We need to mantain a mapping of tid to int ids. We need to have copabale things, and
    pub fn run_value_tracking(&mut self) {
        self.convert();
        self.ascent_prog.run();
        self.debug_print();
    }

    pub fn debug_print(&mut self) {
        println!("Debug Print");
        println!("{}", self);
    }
}

impl Display for ValueTracking<'_> {
    /// We print blk for blk
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Printing Program")?;

        write!(f, "{:#?}", self.ascent_prog.aloc_val_indices_0.0)?;
        for blk in self.program.blocks() {
            writeln!(f, "Block: {}:", blk.tid)?;
            for def in blk.defs() {
                writeln!(f, "\t{}", def)?;
                match &def.term {
                    Def::Load { var, .. } => {
                        let Some(exps) =
                            self.ascent_prog.aloc_val_indices_0.0.get(&(Loc::Reg(Reg {
                                var: var.clone().into(),
                            }),))
                        else {
                            continue;
                        };
                        if !exps.is_empty() {
                            writeln!(
                                f,
                                "\t\t{{{}}}",
                                exps.iter()
                                    .map(|exp| exp.0.to_string())
                                    .collect_vec()
                                    .join(",")
                            )?;
                        }
                    }
                    Def::Store { .. } => (),
                    Def::Assign { var, value } => {
                        let Some(exps) =
                            self.ascent_prog.aloc_val_indices_0.0.get(&(Loc::Reg(Reg {
                                var: var.clone().into(),
                            }),))
                        else {
                            continue;
                        };
                        if !exps.is_empty() {
                            writeln!(
                                f,
                                "\t\t{{{}}}",
                                exps.iter()
                                    .map(|exp| exp.0.to_string())
                                    .collect_vec()
                                    .join(",")
                            )?;
                        }

                        //if let Expression::Phi(vars) = value {
                        //    let phis = self
                        //        .ascent_prog
                        //        .phi_indices_2
                        //        .0
                        //        .get(&(Blk(blk.tid.clone().into()),));
                        //    if let Some(phis) = phis {
                        //        for phi in phis {
                        //            write!(f, "phi({}, {})", phi.0.var.name, phi.1.var.name)?;
                        //        }
                        //    }
                        //};
                    }
                }
            }
        }

        Ok(())
    }
}
