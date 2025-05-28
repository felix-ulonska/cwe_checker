use ascent::{
    hashbrown::HashMap,
    rayon::iter::{IntoParallelRefIterator, ParallelIterator},
};
use itertools::Itertools;

use crate::{
    analysis::indirect_call_recovery::{
        function_taken::Function,
        memory_block_gen::{
            global_block::{self, Interval},
            stack_block::StackBlock,
            BlockMemoryModel,
        },
        value_tracking::{build_union_of_vars, Blk, Hblk, Loc, Reg},
    },
    intermediate_representation::{ir_passes::SPLIT_SYMBOL, Project, Variable},
    prelude::Tid,
};
use std::{collections::HashSet, fmt::Display, sync::Arc, vec::Vec};

use crate::{
    intermediate_representation::{ir_passes::VarsAtEndOfBlock, Def, Expression, Jmp, Program},
    prelude::Bitvector,
};

use super::{
    arc_cache::ArcCache, build_union_of_vars_as_deref, AscentProgram, Exp, Gblk, Mloc, Sblk,
};

pub struct ValueTracking<'a> {
    program: &'a Program,
    project: &'a Project,
    block_memory: &'a BlockMemoryModel,
    at_functions: &'a HashSet<Function>,
    at_functions_by_addr: HashMap<u64, Function>,
    rename_table: &'a std::collections::HashMap<Variable, Variable>,
    active_var_at_end_of_block: &'a VarsAtEndOfBlock,
    var_cache: ArcCache<Variable>,
    blk_cache: ArcCache<Tid>,
    def_cache: ArcCache<Tid>,
    fn_cache: ArcCache<Function>,
    stkblk_cache: ArcCache<StackBlock>,
    interval_cache: ArcCache<Interval>,
    pub ascent_prog: AscentProgram,
}

impl ValueTracking<'_> {
    /// Parse a const addr to exp
    fn parse_const(&mut self, bitvector: &Bitvector) -> Exp {
        let Ok(val) = bitvector.try_to_u64() else {
            return Exp::Empty;
        };

        if let Some(at_function) = self.at_functions_by_addr.get(&val) {
            return Exp::RefFunc(self.fn_cache.get(at_function));
        }

        if let Some(interval) = self.block_memory.global.get_interval(val as i64) {
            return Exp::RefMLoc(Mloc::Gblk(Gblk(self.interval_cache.get(&interval))));
        }

        Exp::Empty
    }

    // THis can convert the bitvector to an exp without a mut reference because it does not utilize
    // caching
    fn parse_const_slow(&self, bitvector: &Bitvector) -> Exp {
        let Ok(val) = bitvector.try_to_u64() else {
            return Exp::Empty;
        };

        if let Some(at_function) = self.at_functions_by_addr.get(&val) {
            return Exp::RefFunc(at_function.clone().into());
        }

        if let Some(interval) = self.block_memory.global.get_interval(val as i64) {
            return Exp::RefMLoc(Mloc::Gblk(Gblk(interval.into())));
        }

        Exp::Empty
    }

    fn expression_to_value_tracking(&mut self, exp: &Expression) -> Exp {
        match exp {
            Expression::Var(var) => Exp::Reg(Reg {
                var: self.var_cache.get(var),
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

    fn expression_to_value_tracking_slow(&self, exp: &Expression) -> Exp {
        match exp {
            Expression::Var(var) => Exp::Reg(Reg {
                var: var.clone().into(),
            }),
            // TODO add infer for function pointer and global pointer
            Expression::Const(bitvector) => self.parse_const_slow(bitvector),
            Expression::BinOp { lhs, rhs, .. } => Exp::Union(
                Arc::new(self.expression_to_value_tracking_slow(&*lhs)),
                Arc::new(self.expression_to_value_tracking_slow(&*rhs)),
            ),
            Expression::UnOp { arg, .. }
            | Expression::Cast { arg, .. }
            | Expression::Subpiece { arg, .. } => self.expression_to_value_tracking_slow(&*arg),
            Expression::Unknown { .. } => panic!(),
            Expression::Phi(vars) => build_union_of_vars(&vars.iter().collect()),
        }
    }

    pub fn new<'a>(
        program: &'a Program,
        project: &'a Project,
        block_memory: &'a BlockMemoryModel,
        at_functions: &'a HashSet<Function>,
        active_var_at_end_of_block: &'a VarsAtEndOfBlock,
        rename_table: &'a std::collections::HashMap<Variable, Variable>,
    ) -> ValueTracking<'a> {
        let mut at_functions_by_addr = HashMap::new();
        for func in at_functions {
            println!(
                "Adding AtFunction {} name {}",
                func.first_instruction, func.name
            );
            at_functions_by_addr.insert(func.first_instruction, func.clone());
        }

        let prog = AscentProgram::default();
        ValueTracking {
            program,
            project,
            block_memory,
            at_functions,
            at_functions_by_addr,
            active_var_at_end_of_block,
            rename_table,
            ascent_prog: prog,
            fn_cache: ArcCache::new(),
            var_cache: ArcCache::new(),
            blk_cache: ArcCache::new(),
            def_cache: ArcCache::new(),
            interval_cache: ArcCache::new(),
            stkblk_cache: ArcCache::new(),
        }
    }

    fn add_code_ptr_in_global_blocks(&mut self) {
        //for code_ref in &self.project.code_references {
        //    let Some(interval) = self.block_memory.global.get_interval(code_ref.from) else {
        //        continue;
        //    };
        //    let Some(at_fn) = self.at_functions_by_addr.get(&(code_ref.to as u64)) else {
        //        continue;
        //    };
        //    self.ascent_prog.aloc_val.push((
        //        Loc::Mloc(Mloc::Gblk(Gblk(self.interval_cache.get(&interval)))),
        //        Exp::RefFunc(self.fn_cache.get(at_fn)),
        //    ));
        //}
    }

    fn interval_to_expr(&mut self, interval: &Interval) -> Exp {
        // Gblk is actually a atfunction
        if let Some(at_func) = self.at_functions_by_addr.get(&(interval.begin as u64)) {
            Exp::RefFunc(self.fn_cache.get(at_func))
        } else {
            Exp::DerefMloc(Mloc::Gblk(Gblk(self.interval_cache.get(&interval))))
        }
    }

    fn inject_gblk_from_global(&mut self, def: &Tid, existing_expr: Exp) -> Exp {
        let Some(val) = self.block_memory.global_values.values_at_defs.get(&def) else {
            return existing_expr;
        };
        let Some(val) = global_block::Interval::try_from_data_domain(val.clone()) else {
            return existing_expr;
        };
        if let Some(at_func) = self.at_functions_by_addr.get(&(val.begin as u64)) {
            return Exp::Union(
                Arc::new(Exp::RefFunc(self.fn_cache.get(at_func))),
                Arc::new(existing_expr),
            );
        } else {
            if let Some(interval) = self.block_memory.global.get_interval(val.begin) {
                return Exp::Union(
                    Arc::new(Exp::RefMLoc(Mloc::Gblk(Gblk(
                        self.interval_cache.get(&interval),
                    )))),
                    Arc::new(existing_expr),
                );
            } else {
                return existing_expr;
            }
        };
    }

    fn convert_def_to_ascent(&mut self) {
        for sub in &self.program.subs {
            for blk in sub.1.blocks() {
                for def in blk.defs() {
                    let _tid = self.def_cache.get(&def.tid);
                    match &def.term {
                        // AssignReg
                        Def::Load { var, address } => {
                            if let Some(interval) =
                                self.block_memory.global.get_interval_of_def(def.clone())
                            {
                                let var = self.var_cache.get(var);
                                let expr = self.interval_to_expr(&interval);
                                self.ascent_prog.assign_reg.push((
                                    Reg { var: var.clone() },
                                    expr,
                                    self.def_cache.get(&def.tid),
                                ));
                                self.ascent_prog.reg_to_block.push((
                                    Reg { var: var.clone() },
                                    Blk(self.blk_cache.get(&blk.tid)),
                                ));
                                continue;
                            }

                            let inputs_vars = address.input_vars();
                            // if inputs_vars.len() == 1 {
                            self.ascent_prog.assign_reg.push((
                                Reg {
                                    var: self.var_cache.get(var),
                                },
                                build_union_of_vars_as_deref(&inputs_vars),
                                //Exp::Deref(Reg {
                                //    var: inputs_vars[0].clone().into(),
                                //}),
                                self.def_cache.get(&def.tid),
                            ));
                        }
                        // AssignMloc
                        Def::Store { address, value } => {
                            if let Some(interval) =
                                self.block_memory.global.get_interval_of_def(def.clone())
                            {
                                let out_expr = self.expression_to_value_tracking(&value);
                                let out_expr = self.inject_gblk_from_global(&_tid, out_expr);
                                self.ascent_prog.assign_mloc.push((
                                    Mloc::Gblk(Gblk(self.interval_cache.get(&interval))),
                                    out_expr,
                                    self.def_cache.get(&def.tid),
                                ));
                                continue;
                            }

                            // TODO: refactor code dupl
                            let input_vars = address.input_vars();
                            for input_var in input_vars {
                                let out_expr = self.expression_to_value_tracking(&value);
                                let out_expr = self.inject_gblk_from_global(&_tid, out_expr);
                                self.ascent_prog.assing_deref_reg.push((
                                    Reg {
                                        var: self.var_cache.get(input_var),
                                    },
                                    out_expr,
                                    self.def_cache.get(&def.tid),
                                ));
                            }
                        }
                        // AssignReg
                        Def::Assign { var, value } => {
                            if let Expression::Phi(vars) = &value {
                                //if self
                                //    .block_memory
                                //    .stack
                                //    .map_register_to_stack
                                //    .contains_key(&var)
                                //{
                                //    continue;
                                //}
                                self.ascent_prog.reg_to_block.push((
                                    Reg {
                                        var: self.var_cache.get(var),
                                    },
                                    Blk(self.blk_cache.get(&blk.tid)),
                                ));
                                for source_var in vars {
                                    self.ascent_prog.phi.push((
                                        Reg {
                                            var: self.var_cache.get(var),
                                        },
                                        Reg {
                                            var: self.var_cache.get(source_var),
                                        },
                                        Blk(blk.tid.clone().into()),
                                    ));
                                }
                            } else {
                                self.ascent_prog.reg_to_block.push((
                                    Reg {
                                        var: self.var_cache.get(var),
                                    },
                                    Blk(self.blk_cache.get(&blk.tid)),
                                ));
                                let out_expr = self.expression_to_value_tracking(&value);

                                if let Some(interval) =
                                    self.block_memory.global.get_interval_of_def(def.clone())
                                {
                                    println!("Got expr for {}: {}", def.tid, interval);
                                    let exp = self.interval_to_expr(&interval);
                                    self.ascent_prog.aloc_val.push((
                                        Loc::Reg(Reg {
                                            var: self.var_cache.get(var),
                                        }),
                                        exp,
                                    ));
                                }

                                // SKIP if rsp_X = rsp_Y + empty
                                // If the register has a stack block assgined to it, prevent
                                // propogation via RSP value tracking. RSP_{X+1} = RSP_X - 8. Values
                                // from RSP_X should not propogate
                                //if found_stack_vars == 1
                                //    && found_regs == 1
                                //    && self
                                //        .block_memory
                                //        .stack
                                //        .map_register_to_stack
                                //        .contains_key(&var)
                                //{
                                //    continue;
                                //}
                                self.ascent_prog.assign_reg.push((
                                    Reg {
                                        var: self.var_cache.get(var),
                                    },
                                    out_expr,
                                    self.def_cache.get(&def.tid),
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    fn add_values_from_global_analysis(&mut self) {
        for blk in self.program.blocks() {
            for def in blk.defs() {
                let (Def::Load { var, .. } | Def::Assign { var, .. }) = &def.term else {
                    continue;
                };
                let Some(val) = self.block_memory.global_values.values_at_defs.get(&def.tid) else {
                    continue;
                };
                let Some(val) = global_block::Interval::try_from_data_domain(val.clone()) else {
                    continue;
                };
                let expr = if let Some(at_func) = self.at_functions_by_addr.get(&(val.begin as u64))
                {
                    Exp::RefFunc(self.fn_cache.get(at_func))
                } else {
                    if let Some(interval) = self.block_memory.global.get_interval(val.begin) {
                        Exp::RefMLoc(Mloc::Gblk(Gblk(self.interval_cache.get(&interval))))
                    } else {
                        continue;
                    }
                };
                self.ascent_prog.assign_reg.push((
                    Reg {
                        var: self.var_cache.get(var),
                    },
                    expr,
                    self.def_cache.get(&def.tid),
                ));
            }
        }
    }

    // Add call xx ret yy
    // Build a table for mapping XX -> YY
    fn add_next_block_from_call(&mut self) {
        for blk in self.program.blocks() {
            for jmp in &blk.jmps {
                if let Jmp::Call {
                    target: _,
                    return_: Some(return_),
                }
                | Jmp::CallInd {
                    target: _,
                    return_: Some(return_),
                } = &jmp.term
                {
                    self.ascent_prog.ret_of_icall.push((
                        Blk(self.blk_cache.get(&blk.tid)),
                        Blk(self.blk_cache.get(return_)),
                    ));
                }
            }
        }
    }

    fn add_live_at_begin_and_end(&mut self) {
        for blk in self.program.blocks() {
            let mut currrent_active_vars = HashMap::new();
            for def in blk.defs() {
                if let Def::Assign {
                    var,
                    value: Expression::Phi(..),
                } = &def.term
                {
                    self.ascent_prog.live_at_start.push((
                        Reg {
                            var: self.var_cache.get(&var),
                        },
                        Blk(self.blk_cache.get(&blk.tid)),
                    ));
                }
            }
            for def in blk.defs() {
                if let Def::Load { var, .. } | Def::Assign { var, .. } = &def.term {
                    currrent_active_vars.insert(var.name.split_once(SPLIT_SYMBOL).unwrap().0, var);
                }
            }
            for (_base_var, var) in currrent_active_vars.iter() {
                self.ascent_prog.live_at_end.push((
                    Reg {
                        var: self.var_cache.get(&var),
                    },
                    Blk(self.blk_cache.get(&blk.tid)),
                ));
            }
        }
    }

    fn add_vals_from_global_content_analysis(&mut self) {
        for (global_block, content_vec) in self.block_memory.global.iter_content() {
            for content in content_vec {
                let content_expr = if let Some(at_func) = self.at_functions_by_addr.get(content) {
                    Exp::RefFunc(self.fn_cache.get(at_func))
                } else {
                    if let Some(interval) = self.block_memory.global.get_interval(*content as i64) {
                        Exp::DerefMloc(Mloc::Gblk(Gblk(self.interval_cache.get(&interval))))
                    } else {
                        continue;
                    }
                };
                self.ascent_prog.aloc_val.push((
                    Loc::Mloc(Mloc::Gblk(Gblk(self.interval_cache.get(&global_block)))),
                    content_expr,
                ));
            }
        }
    }

    fn add_return_statements(&mut self) {
        for (tid, term) in &self.program.subs {
            let Some(at_func) = self
                .at_functions
                .par_iter()
                .find_any(|at_fun| at_fun.tid == *tid)
            else {
                println!("Warning: Missing AT Function");
                continue;
            };

            for blk in term.blocks() {
                for jmp in blk.jmps() {
                    // assume: no mods to ret register. We return to the call instr
                    if let Jmp::Return(..) = &jmp.term {
                        self.ascent_prog.block_with_return_of_at_function.push((
                            Blk(self.blk_cache.get(&blk.tid)),
                            self.fn_cache.get(at_func),
                        ));
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
                            Blk(self.blk_cache.get(&blk.tid)),
                        ));
                    }
                }
            }
        }
    }

    fn replace_var_from_rename_table_and_get_cache(&mut self, var: Variable) -> Arc<Variable> {
        self.var_cache
            .get(&self.rename_table.get(&var).cloned().unwrap_or(var))
    }

    fn add_reg_to_block(&mut self) {
        for (blk, active_vars) in self.active_var_at_end_of_block {
            for var in active_vars {
                let var = self.replace_var_from_rename_table_and_get_cache(var.clone());
                self.ascent_prog
                    .reg_to_block
                    .push((Reg { var }, Blk(self.blk_cache.get(&blk))));
            }
        }
    }

    fn add_atfunc_to_block(&mut self) {
        for atfunction in self.at_functions {
            self.ascent_prog.atfunc_to_block.push((
                self.fn_cache.get(atfunction),
                Blk(self.blk_cache.get(&atfunction.first_block_tid)),
            ));
        }
    }

    fn add_block_to_func(&mut self) {
        for (sub_tid, sub) in &self.program.subs {
            println!("added funcID {}", sub_tid);
            for blk in &sub.blocks {
                self.ascent_prog
                    .block_to_func
                    .push((Blk(self.blk_cache.get(&blk.tid)), sub_tid.clone().into()));
            }
        }
    }

    fn add_heap_aloc_val(&mut self) {
        // inject heap values:
        //      Orignal: target_reg <- &heap
        // Represent as:
        //      Add temp_var <- &Mloc(heap)
        //      Add phi(target_reg, temp_var)
        for (heap_target_var, heap_blk) in &self.block_memory.heap.register_with_heap {
            let var = self.replace_var_from_rename_table_and_get_cache(heap_target_var.clone());
            self.ascent_prog.aloc_val.push((
                Loc::Reg(Reg { var }),
                Exp::RefMLoc(Mloc::Hblk(Hblk(Arc::new(heap_blk.clone())))),
            ));
        }
    }

    fn add_stack_aloc_val(&mut self) {
        for (stack_target_var, stack_blk) in &self.block_memory.stack.map_register_to_stack {
            // This may be unsound.
            //let var = self.replace_var_from_rename_table_and_get_cache(stack_target_var.clone());
            self.ascent_prog.aloc_val.push((
                Reg {
                    var: stack_target_var.clone().into(),
                }
                .into(),
                Exp::RefMLoc(Mloc::Sblk(Sblk(self.stkblk_cache.get(stack_blk)))),
            ));
        }

        for (_, vars) in self.active_var_at_end_of_block {
            for var in vars {
                if self.project.stack_pointer_register.name
                    == var.name.split_once(SPLIT_SYMBOL).unwrap().0
                {
                    self.ascent_prog.stack_registers.push((Reg {
                        var: self.var_cache.get(var),
                    },));
                }
            }
        }
    }

    fn fill_base_reg_mapping(&mut self) {
        for blk in self.program.blocks() {
            for def in blk.defs() {
                if let Def::Assign { var, .. } = &def.term {
                    let base_reg_name = var.name.split(SPLIT_SYMBOL).collect_vec()[0];
                    self.ascent_prog.base_reg.push((
                        Reg {
                            var: self.var_cache.get(var),
                        },
                        Reg {
                            var: self.var_cache.get(&Variable {
                                name: base_reg_name.to_string(),
                                size: var.size,
                                is_temp: var.is_temp,
                            }),
                        },
                    ));
                }
            }
        }
    }

    fn convert_calling_conv(&mut self) {
        let Some(call_convention) = self.project.get_standard_calling_convention() else {
            return;
        };
        for param in call_convention.get_all_parameter_register() {
            for reg in self.var_cache.get_all() {
                if reg.name.contains(&param.name) {
                    self.ascent_prog.param_regs.push((Reg {
                        var: self.var_cache.get(&reg),
                    },));
                }
            }
        }
        for param in call_convention.get_all_return_register() {
            for reg in self.var_cache.get_all() {
                if reg.name.contains(&param.name) {
                    self.ascent_prog.ret_regs.push((Reg {
                        var: self.var_cache.get(&reg),
                    },));
                }
            }
        }
    }

    pub fn convert(&mut self) {
        eprintln!("Starting to convert");
        self.convert_def_to_ascent();
        eprintln!("Converted def");
        self.add_reg_to_block();
        eprintln!("Converted Reg To blk");
        self.add_atfunc_to_block();
        eprintln!("Converted AtFunc");
        self.add_stack_aloc_val();
        eprintln!("Converted StackAlloc");
        self.add_used_func_call();
        eprintln!("Converted UsedFunc");
        self.add_heap_aloc_val();
        eprintln!("Converted Alocval");
        self.add_return_statements();
        eprintln!("Converted Return");
        self.fill_base_reg_mapping();
        eprintln!("Converted fill_base_reg_mapping");
        self.add_code_ptr_in_global_blocks();
        eprintln!("Add global code pointer");
        self.add_block_to_func();
        eprintln!("Add val from global analysis");
        self.add_values_from_global_analysis();
        self.add_vals_from_global_content_analysis();
        self.convert_calling_conv();
        self.add_live_at_begin_and_end();
        self.add_next_block_from_call();
        self.statistic();
    }

    fn statistic(&self) {
        println!(
            "PRE_EVAL size \n{}",
            self.ascent_prog.relation_sizes_summary()
        );
        println!("Global Blocks: {}", self.block_memory.global.count_blocks());
        println!(
            "Heap Blocks: {}",
            self.block_memory.heap.count_heap_blocks()
        );
        println!(
            "Stack Blocks: {}",
            self.block_memory.stack.count_stack_blocks()
        );
    }

    // We need to mantain a mapping of tid to int ids. We need to have copabale things, and
    pub fn run_value_tracking_with_debug(&mut self) {
        eprintln!("Starting to run ascent_prog");
        self.ascent_prog.run();
        //self.ascent_prog.run_timeout(Duration::from_secs(60 * 10));
        println!("{}", self.ascent_prog.scc_times_summary());
        self.debug_print();
        self.print_results();
    }

    fn print_results(&self) {
        let mut results: HashMap<Blk, Vec<Arc<Function>>> = HashMap::new();
        for (blk, func) in &self.ascent_prog.func_call_targets {
            results.entry(blk.clone()).or_default().push(func.clone());
        }
        println!("CallGraph:");
        for sub in &self.program.subs {
            println!("{}:", sub.1.name);
            for blk in sub.1.blocks() {
                let Some(bs) = results.get(&Blk(blk.tid.clone().into())) else {
                    continue;
                };
                println!("\t{}:", blk.tid);
                for b in bs {
                    println!("\t\t{b}");
                }
            }
        }
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
                    let Some(exps) = self
                        .ascent_prog
                        .aloc_val_indices_0
                        .unwrap_unfrozen()
                        .get(&(reg.into(),))
                    else {
                        continue;
                    };
                    for exp in exps.iter() {
                        refered_values.push(exp.0.clone());
                    }
                }
                Exp::RefMLoc(mloc) => {
                    let Some(exps) = self
                        .ascent_prog
                        .aloc_val_indices_0
                        .unwrap_unfrozen()
                        .get(&(mloc.into(),))
                    else {
                        continue;
                    };
                    for exp in exps.iter() {
                        refered_values.push(exp.0.clone());
                    }
                }
                Exp::Deref(_) | Exp::RefFunc(_) => {
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
                    let Some(exps) = self
                        .ascent_prog
                        .aloc_val_indices_0
                        .unwrap_unfrozen()
                        .get(&(reg.into(),))
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
                    for exp in exps.iter() {
                        if let Exp::RefMLoc(mloc) = &exp.0 {
                            refered_values.push(mloc.clone());
                        }
                    }
                }
                //Exp::Mloc(mloc) => refered_values.push(mloc.into()),
                Exp::Deref(_) => (),
                Exp::DerefMloc(_) => (),
                Exp::RefMLoc(mloc) => refered_values.push(mloc.into()),
                Exp::RefFunc(_) => (),
                Exp::Union(_, _) => (),
            }
        }

        refered_values
    }

    fn get_assigns(&self, tid: &Tid) -> Vec<(Loc, Exp, Arc<Tid>)> {
        let mut assigns = vec![];
        for assign in &self.ascent_prog.assign {
            if *assign.2 == *tid {
                assigns.push(assign.clone());
            }
        }
        return assigns;
    }

    fn _refed_values(&self, f: &mut std::fmt::Formatter, exp: &Exp) -> std::fmt::Result {
        //let mut refered_values = vec![];
        for value in exp.to_iter() {
            //if let Exp::RefMLoc(ref ref_mloc) = value {
            //    refered_values.push(ref_mloc.clone());
            //}
            //if let Exp::RefFunc(ref ref_func) = value {
            //    refered_values.push(ref_func.clone());
            //}
            let Some(exps) = self
                .ascent_prog
                .aloc_val_indices_0
                .unwrap_unfrozen()
                .get(&(value.into(),))
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
        Ok(())
    }
}

impl Display for ValueTracking<'_> {
    /// We print blk for blk
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Printing Program")?;

        for sub in &self.program.subs {
            //if sub.1.name != "newline" && !sub.1.name.starts_with("test") {
            //    continue;
            //}
            write!(f, "==== {} ====", sub.1.name)?;
            for blk in sub.1.blocks() {
                writeln!(f, "Block: {}:", blk.tid)?;
                for def in blk.defs() {
                    writeln!(f, "\t{}", def)?;
                    match &def.term {
                        Def::Load { var, address } => {
                            for assign in self.get_assigns(&def.tid) {
                                writeln!(f, "\t\t[!]{} := {}", assign.0, assign.1)?;
                            }
                            write!(f, "\t\t{} <-- ", var.name)?;
                            writeln!(
                                f,
                                "{}",
                                self.refed_mem_locs(
                                    &self.expression_to_value_tracking_slow(address)
                                )
                                .iter()
                                .map(|exp| exp.to_string())
                                .collect_vec()
                                .join(",")
                            )?;
                            let Some(exps) =
                                self.ascent_prog.aloc_val_indices_0.unwrap_unfrozen().get(&(
                                    Loc::Reg(Reg {
                                        var: var.clone().into(),
                                    }),
                                ))
                            else {
                                writeln!(f, "\t\t{} := {{}}", var.name)?;
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
                        Def::Store { address, value } => {
                            for assign in self.get_assigns(&def.tid) {
                                writeln!(f, "\t\t[!]{} := {}", assign.0, assign.1)?;
                            }
                            write!(
                                f,
                                "\t\t{}",
                                self.refed_mem_locs(
                                    &self.expression_to_value_tracking_slow(address)
                                )
                                .iter()
                                .map(|exp| exp.to_string())
                                .collect_vec()
                                .join(",")
                            )?;
                            writeln!(
                                f,
                                "+= {}",
                                self.value_set(&self.expression_to_value_tracking_slow(value))
                                    .iter()
                                    .map(|exp| exp.to_string())
                                    .collect_vec()
                                    .join(",")
                            )?;
                            for refed_locs in self
                                .refed_mem_locs(&self.expression_to_value_tracking_slow(address))
                            {
                                let Some(exps) = self
                                    .ascent_prog
                                    .aloc_val_indices_0
                                    .unwrap_unfrozen()
                                    .get(&(Loc::Mloc(refed_locs.clone().into()),))
                                else {
                                    continue;
                                };
                                write!(f, "\t\t{} :=", refed_locs)?;
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
                        Def::Assign { var, value } => {
                            if let Expression::Phi(..) = value {
                                let phi_funcs = self.ascent_prog.phi.iter().filter(|phi| {
                                    phi.0
                                        == Reg {
                                            var: var.clone().into(),
                                        }
                                });
                                write!(f, "[!]\t\t{} <-- phi(", var.name)?;
                                for phi_func in phi_funcs {
                                    write!(f, "{},", phi_func.1.var.name)?;
                                }
                                writeln!(f, ")")?;
                            }
                            for assign in self.get_assigns(&def.tid) {
                                writeln!(f, "\t\t[!]{} := {}", assign.0, assign.1)?;
                            }
                            let Some(exps) =
                                self.ascent_prog.aloc_val_indices_0.unwrap_unfrozen().get(&(
                                    Loc::Reg(Reg {
                                        var: var.clone().into(),
                                    }),
                                ))
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

        //let mut all_locs = HashSet::new();
        //for (loc, _) in &self.ascent_prog.aloc_val {
        //    all_locs.insert(loc);
        //}

        //for loc in all_locs {
        //    writeln!(f, "{}: ", loc)?;
        //    let Some(exps) = self
        //        .ascent_prog
        //        .aloc_val_indices_0
        //        .unwrap_unfrozen()
        //        .get(&(loc.clone(),))
        //    else {
        //        continue;
        //    };
        //    for exp in exps.iter() {
        //        writeln!(f, "'\t{}: ", exp.0)?;
        //    }
        //}

        Ok(())
    }
}
