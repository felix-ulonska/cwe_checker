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
    vec::{self, Vec},
};

use crate::{
    intermediate_representation::{
        ir_passes::VarsAtEndOfBlock, Def, Expression, Jmp, Program, Variable,
    },
    prelude::{Bitvector, ByteSize},
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
                        if let Expression::Phi(vars) = &value {
                            self.ascent_prog.reg_to_block.push((
                                Reg {
                                    var: var.clone().into(),
                                },
                                Blk(Arc::new(blk.tid.clone())),
                            ));
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
            println!("AtFunc to {}", atfunction.tid);
            self.ascent_prog.atfunc_to_block.push((
                atfunction.clone(),
                Blk(atfunction.first_block_tid.clone().into()),
            ));
        }
    }

    fn add_heap_aloc_val(&mut self) {
        // inject heap values:
        //      Orignal: target_reg <- &heap
        // Represent as:
        //      Add temp_var <- &Mloc(heap)
        //      Add phi(target_reg, temp_var)
        for (heap_target_var, heap_blk) in &self.block_memory.heap.register_with_heap {
            self.ascent_prog.aloc_val.push((
                Loc::Reg(Reg {
                    var: Arc::new(heap_target_var.clone()),
                }),
                Exp::RefMLoc(Mloc::Hblk(Hblk(Arc::new(heap_blk.clone())))),
            ));
        }
    }

    fn add_stack_aloc_val(&mut self) {
        for (stack_target_var, stack_blk) in &self.block_memory.stack.map_register_to_stack {
            println!(
                "Adding stack block {} <- {}",
                stack_target_var, stack_blk.func_tid
            );
            self.ascent_prog.aloc_val.push((
                Reg {
                    var: Arc::new(stack_target_var.clone()),
                }
                .into(),
                Exp::RefMLoc(Mloc::Sblk(Sblk(Arc::new(stack_blk.clone())))),
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

    fn value_set(&self, exp: &Exp) -> Vec<Exp> {
        let mut refered_values = vec![];
        for value in exp.to_iter() {
            match value {
                Exp::Empty => (),
                Exp::Reg(reg) => {
                    let Some(exps) = self.ascent_prog.aloc_val_indices_0.0.get(&(reg.into(),))
                    else {
                        continue;
                    };
                    for exp in exps {
                        refered_values.push(exp.0.clone());
                    }
                }
                Exp::Mloc(mloc) => {
                    let Some(exps) = self.ascent_prog.aloc_val_indices_0.0.get(&(mloc.into(),))
                    else {
                        continue;
                    };
                    for exp in exps {
                        refered_values.push(exp.0.clone());
                    }
                }
                Exp::Deref(_) | Exp::RefMLoc(_) | Exp::RefFunc(_) => {
                    refered_values.push(exp.clone());
                }
                _ => (),
            }
        }

        refered_values
    }

    fn refed_mem_locs(&self, exp: &Exp) -> Vec<Mloc> {
        let mut refered_values = vec![];
        for value in exp.to_iter() {
            match value {
                Exp::Empty => (),
                Exp::Reg(reg) => {
                    let Some(exps) = self.ascent_prog.aloc_val_indices_0.0.get(&(reg.into(),))
                    else {
                        continue;
                    };
                    //println!(
                    //    "Got exps {}",
                    //    exps.iter()
                    //        .map(|exp| exp.0.to_string())
                    //        .collect_vec()
                    //        .join(",")
                    //);
                    for exp in exps {
                        if let Exp::Mloc(mloc) = &exp.0 {
                            refered_values.push(mloc.clone());
                        }
                        if let Exp::RefMLoc(mloc) = &exp.0 {
                            refered_values.push(mloc.clone());
                        }
                    }
                }
                Exp::Mloc(mloc) => refered_values.push(mloc.into()),
                Exp::Deref(_) => (),
                Exp::RefMLoc(_) => (),
                Exp::RefFunc(_) => (),
                Exp::Union(_, _) => (),
            }
        }

        refered_values
    }

    fn refed_values(&self, f: &mut std::fmt::Formatter<'_>, exp: &Exp) -> std::fmt::Result {
        //let mut refered_values = vec![];
        for value in exp.to_iter() {
            //if let Exp::RefMLoc(ref ref_mloc) = value {
            //    refered_values.push(ref_mloc.clone());
            //}
            //if let Exp::RefFunc(ref ref_func) = value {
            //    refered_values.push(ref_func.clone());
            //}
            let Some(exps) = self.ascent_prog.aloc_val_indices_0.0.get(&(value.into(),)) else {
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
        Ok(())
    }
}

impl Display for ValueTracking<'_> {
    /// We print blk for blk
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Printing Program")?;

        for sub in &self.program.subs {
            if sub.1.name != "main" && !sub.1.name.starts_with("test") {
                continue;
            }
            write!(f, "==== {} ====", sub.1.name)?;
            for blk in sub.1.blocks() {
                writeln!(f, "Block: {}:", blk.tid)?;
                for def in blk.defs() {
                    writeln!(f, "\t{}", def)?;
                    match &def.term {
                        Def::Load { var, address } => {
                            write!(f, "\t\t{} := ", var.name)?;
                            writeln!(
                                f,
                                "{}",
                                self.refed_mem_locs(&self.expression_to_value_tracking(address))
                                    .iter()
                                    .map(|exp| exp.to_string())
                                    .collect_vec()
                                    .join(",")
                            )?;
                        }
                        Def::Store { address, value } => {
                            write!(
                                f,
                                "\t\t{}",
                                self.refed_mem_locs(&self.expression_to_value_tracking(address))
                                    .iter()
                                    .map(|exp| exp.to_string())
                                    .collect_vec()
                                    .join(",")
                            )?;
                            writeln!(
                                f,
                                ":= {}",
                                self.value_set(&self.expression_to_value_tracking(value))
                                    .iter()
                                    .map(|exp| exp.to_string())
                                    .collect_vec()
                                    .join(",")
                            )?;
                        }
                        Def::Assign { var, value } => {
                            let Some(exps) =
                                self.ascent_prog.aloc_val_indices_0.0.get(&(Loc::Reg(Reg {
                                    var: var.clone().into(),
                                }),))
                            else {
                                continue;
                            };
                            write!(f, "\t\t{} :=", var.name)?;
                            if !exps.is_empty() {
                                writeln!(
                                    f,
                                    "{{{}}}",
                                    exps.iter()
                                        .map(|exp| exp.0.to_string())
                                        .collect_vec()
                                        .join(",")
                                )?;
                            }
                        }
                    }
                }

                for jmp in blk.jmps() {
                    writeln!(f, "\t{}", jmp)?;
                    if let Jmp::CallInd { .. } = jmp.term {
                        for (_blk, target) in &self.ascent_prog.func_call_targets {
                            if *_blk.0 == blk.tid {
                                writeln!(f, "\t\t{}", target)?;
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
