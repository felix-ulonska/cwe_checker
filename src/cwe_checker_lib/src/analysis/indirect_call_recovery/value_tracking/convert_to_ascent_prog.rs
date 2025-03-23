use ascent::rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use itertools::Itertools;

use crate::{
    analysis::indirect_call_recovery::{
        function_taken::Function,
        memory_block_gen::{stack_block::StackBlock, BlockMemoryModel},
        value_tracking::{build_union_of_vars, Blk, Hblk, Loc, Reg},
    },
    intermediate_representation::{ir_passes::SPLIT_SYMBOL, Variable},
    prelude::Tid,
};
use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
    sync::Arc,
    time::Duration,
    vec::Vec,
};

use crate::{
    intermediate_representation::{ir_passes::VarsAtEndOfBlock, Def, Expression, Jmp, Program},
    prelude::Bitvector,
};

use super::{
    arc_cache::ArcCache, build_union_of_vars_as_deref, AscentProgram, Exp, Gblk, Mloc, Sblk,
};

pub struct ValueTracking<'a> {
    program: &'a Program,
    block_memory: &'a BlockMemoryModel,
    at_functions: &'a HashSet<Function>,
    at_functions_by_addr: HashMap<u64, Function>,
    active_var_at_end_of_block: &'a VarsAtEndOfBlock,
    var_cache: ArcCache<Variable>,
    blk_cache: ArcCache<Tid>,
    def_cache: ArcCache<Tid>,
    fn_cache: ArcCache<Function>,
    stkblk_cache: ArcCache<StackBlock>,
    ascent_prog: AscentProgram,
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
            return Exp::RefMLoc(Mloc::Gblk(Gblk(interval.clone())));
        }

        Exp::Empty
    }

    fn parse_const_slow(&self, bitvector: &Bitvector) -> Exp {
        let Ok(val) = bitvector.try_to_u64() else {
            return Exp::Empty;
        };

        if let Some(at_function) = self.at_functions_by_addr.get(&val) {
            return Exp::RefFunc(at_function.clone().into());
        }

        if let Some(interval) = self.block_memory.global.get_interval(val as i64) {
            return Exp::RefMLoc(Mloc::Gblk(Gblk(interval.clone())));
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
        block_memory: &'a BlockMemoryModel,
        at_functions: &'a HashSet<Function>,
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
            fn_cache: ArcCache::new(),
            var_cache: ArcCache::new(),
            blk_cache: ArcCache::new(),
            def_cache: ArcCache::new(),
            stkblk_cache: ArcCache::new(),
        }
    }

    fn convert_def_to_ascent(&mut self) {
        for blk in self.program.blocks() {
            for def in blk.defs() {
                let _tid = self.def_cache.get(&def.tid);
                match &def.term {
                    // AssignReg
                    Def::Load { var, address } => {
                        if let Some(interval) =
                            self.block_memory.global.get_interval_of_def(def.clone())
                        {
                            let var = self.var_cache.get(var);
                            self.ascent_prog.assign_reg.push((
                                Reg { var: var.clone() },
                                Exp::RefMLoc(Mloc::Gblk(Gblk(interval.clone()))),
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
                            self.ascent_prog.assign_mloc.push((
                                Mloc::Gblk(Gblk(interval.clone())),
                                out_expr,
                                self.def_cache.get(&def.tid),
                            ));
                            continue;
                        }

                        // TODO: refactor code dupl
                        let input_vars = address.input_vars();
                        for input_var in input_vars {
                            let out_expr = self.expression_to_value_tracking(&value);
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

    fn add_reg_to_block(&mut self) {
        for (blk, active_vars) in self.active_var_at_end_of_block {
            for var in active_vars {
                self.ascent_prog.reg_to_block.push((
                    Reg {
                        var: Arc::new(var.clone()),
                    },
                    Blk(self.blk_cache.get(&blk)),
                ));
            }
        }
    }

    fn add_atfunc_to_block(&mut self) {
        for atfunction in self.at_functions {
            println!("AtFunc to {}", atfunction.tid);
            self.ascent_prog.atfunc_to_block.push((
                self.fn_cache.get(atfunction),
                Blk(self.blk_cache.get(&atfunction.first_block_tid)),
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
                    var: self.var_cache.get(&heap_target_var),
                }),
                Exp::RefMLoc(Mloc::Hblk(Hblk(Arc::new(heap_blk.clone())))),
            ));
        }
    }

    fn add_stack_aloc_val(&mut self) {
        for (stack_target_var, stack_blk) in &self.block_memory.stack.map_register_to_stack {
            println!("Adding stack block {} <- {}", stack_target_var, stack_blk);
            self.ascent_prog.aloc_val.push((
                Reg {
                    var: self.var_cache.get(stack_target_var),
                }
                .into(),
                Exp::RefMLoc(Mloc::Sblk(Sblk(self.stkblk_cache.get(stack_blk)))),
            ));
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

    fn convert(&mut self) {
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
    }

    // We need to mantain a mapping of tid to int ids. We need to have copabale things, and
    pub fn run_value_tracking(&mut self) {
        self.convert();
        println!("Starting to run ascent_prog");
        //self.ascent_prog.run();
        self.ascent_prog.run_timeout(Duration::from_secs(60 * 10));
        println!("{}", self.ascent_prog.scc_times_summary());
        //self.debug_print();
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
                Exp::RefMLoc(mloc) => refered_values.push(mloc.into()),
                Exp::RefFunc(_) => (),
                Exp::Union(_, _) => (),
            }
        }

        refered_values
    }

    fn get_assign(&self, tid: &Tid) -> Option<(Loc, Exp, Arc<Tid>)> {
        for assign in &self.ascent_prog.assign {
            if *assign.2 == *tid {
                return Some(assign.clone());
            }
        }
        return None;
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
                            if let Some(assign) = self.get_assign(&def.tid) {
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
                            if let Some(assign) = self.get_assign(&def.tid) {
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
                            if let Some(assign) = self.get_assign(&def.tid) {
                                writeln!(f, "[!]\t\t{} := {}", assign.0, assign.1)?;
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

        let mut all_locs = HashSet::new();
        for (loc, _) in &self.ascent_prog.aloc_val {
            all_locs.insert(loc);
        }

        for loc in all_locs {
            writeln!(f, "{}: ", loc)?;
            let Some(exps) = self
                .ascent_prog
                .aloc_val_indices_0
                .unwrap_unfrozen()
                .get(&(loc.clone(),))
            else {
                continue;
            };
            for exp in exps.iter() {
                writeln!(f, "'\t{}: ", exp.0)?;
            }
        }

        Ok(())
    }
}
