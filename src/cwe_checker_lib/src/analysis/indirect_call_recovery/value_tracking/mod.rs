use std::{rc::Rc, sync::Arc};

use crate::{intermediate_representation::{Def, Expression, Program, Variable}, prelude::ByteSize};

use ascent::ascent;
use itertools::Itertools;

use super::memory_block_gen::{global_block::Interval, BlockMemoryModel};

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
pub struct Func(Symbol);

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct Mblk(Symbol);

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct Sblk(Symbol);

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct Hblk(Symbol);

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct Gblk(Interval);

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct Reg { var: Arc<Variable> }

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
    Reg(Reg),
    Mloc(Mloc),
    Deref(Reg),
    RefMLoc(Mloc),
    RefFunc(Func),
    Union(Arc<Exp>, Arc<Exp>)
}

ascent! {
    relation assign_reg(Reg, Exp);
    relation assign_mloc(Mloc, Exp);
    relation assing_deref_reg(Reg, Exp);
    relation undeterministic_assign(Reg, Mloc, Exp);
    relation phi(Reg, Reg);

    relation aloc_val(Loc, Exp);

    relation vset(Exp, Exp);

    vset(Exp::Mloc(val.clone()), content) <-- aloc_val(?Loc::Mloc(val), content);
    vset(Exp::Reg(val.clone()), content) <-- aloc_val(?Loc::Reg(val), content);
    vset(Exp::Deref(val.clone()), content) <-- 
        aloc_val(?Loc::Reg(val), ?Exp::Mloc(mloc)),
        aloc_val(Loc::Mloc(mloc.clone()), content);
    // TODO: missing &func

    //aloc_val(loc, val) <-- aloc_val(loc, val) if let Loc::Reg(reg) = loc;
    // AddrMloc and 
    aloc_val(Loc::Reg(ireg.clone()), Exp::Mloc(exp.clone())) <-- assign_reg(ireg, ?Exp::Mloc(exp));
    // AddrFunc
    aloc_val(Loc::Reg(ireg.clone()), Exp::RefFunc(exp.clone())) <-- assign_reg(ireg, ?Exp::RefFunc(exp));
    // IReg
    aloc_val(Loc::Reg(ireg.clone()), val) <-- assign_reg(ireg, exp), aloc_val(Loc::Reg(ireg.clone()), val);
    // MLoc
    aloc_val(Loc::Mloc(mloc.clone()), val) <-- assign_mloc(mloc, exp), aloc_val(Loc::Mloc(mloc.clone()), val);
    // DIreg
    aloc_val(Loc::Reg(ireg.clone()), val) <--
        assign_reg(ireg, ?Exp::Deref(src_reg)),
        aloc_val(Loc::Reg(src_reg.clone()), ?Exp::RefMLoc(mloc)),
        aloc_val(Loc::Mloc(mloc.clone()), val);
    // AltMloc TODO
    
    // Phi
    aloc_val(Loc::Reg(ireg.clone()), val) <-- phi(ireg, sreg), aloc_val(Loc::Reg(sreg.clone()), val);
}

/// Converts an Vec<Variable> to Tree like Exp expressions where the expressions is a union of all
/// possible vars
fn build_union_of_vars(vars: &Vec<&Variable>) -> Exp {
    let mut exps = vars.into_iter().map(|var| Exp::Reg(Reg { var: Arc::new(var.clone().clone()) })).collect_vec();

    // Terminates as each iter, 2 pops and 1 add.
    while exps.len() > 1 {
        let exp_first = exps.pop().unwrap();
        let exp_second = exps.pop().unwrap();
        exps.push(Exp::Union(Arc::new(exp_first), Arc::new(exp_second)));
    }

    exps.pop().expect("The function should not be called with no input var")
}

fn expression_to_value_tracking(exp: &Expression) -> Exp {
    match exp {
        Expression::Var(var) => Exp::Reg(Reg { var: var.clone().into() }),
        // TODO add infer for function pointer and global pointer
        Expression::Const(_) => todo!(),
        Expression::BinOp { lhs, rhs, .. } => Exp::Union(Arc::new(expression_to_value_tracking(&*lhs)), Arc::new(expression_to_value_tracking(&*rhs))),
        Expression::UnOp { arg, .. }
            | Expression::Cast { arg, .. }
            | Expression::Subpiece { arg, .. } => expression_to_value_tracking(&*arg), 
        Expression::Unknown { .. } => panic!(),
        Expression::Phi(vars) => build_union_of_vars(&vars.iter().collect())
    }
}

// We need to mantain a mapping of tid to int ids. We need to have copabale things, and 
pub fn run_value_tracking(program: &Program, block_memory: &BlockMemoryModel) {
    let mut prog = AscentProgram::default();
    
    prog.assign_reg = vec![];
    prog.assign_mloc = vec![];
    prog.assing_deref_reg = vec![];
    prog.undeterministic_assign = vec![];

    for blk in program.blocks() {
        for def in blk.defs() {
            let _tid = def.tid.clone();
            match &def.term {
                // AssignReg
                Def::Load { var, address } => {
                    if let Some(interval) = block_memory.global.get_interval_of_def(def.clone()) {
                        prog.assign_reg.push((Reg { var: Arc::new(var.clone()) }, Exp::Mloc(Mloc::Gblk(Gblk(interval.clone())))));
                        continue;
                    }

                    let inputs_vars = address.input_vars();
                    if inputs_vars.len() == 1 {
                        prog.assign_reg.push((Reg { var: Arc::new(var.clone()) }, Exp::Reg(Reg { var: Arc::new(inputs_vars[0].clone()) })));
                    } else if inputs_vars.len() > 1 {
                        // Build temp variable which includes all possible inputs
                        let temp_var = Arc::new(Variable {
                            name: format!("tempSrcAddrFor{}", var.name),
                            size: var.size,
                            is_temp: true
                        });
                        prog.assign_reg.push((Reg { var: temp_var.clone()}, build_union_of_vars(&inputs_vars)));
                        prog.assign_reg.push((Reg { var: Arc::new(var.clone()) }, Exp::Reg(Reg { var: temp_var })));
                    }
                },
                // AssignMloc
                Def::Store { address, value } => {
                    if let Some(interval) = block_memory.global.get_interval_of_def(def.clone()) {
                        prog.assign_mloc.push((Mloc::Gblk(Gblk(interval.clone())), expression_to_value_tracking(value)));
                        continue;
                    }

                    // TODO: refactor code dupl
                    let input_vars = address.input_vars();
                    if input_vars.len() == 1 {
                        prog.assing_deref_reg.push((Reg { var: Arc::new(input_vars[0].clone()) }, Exp::Reg(Reg { var: Arc::new(input_vars[0].clone()) })));
                    } else if input_vars.len() > 1 {
                        // Build temp variable which includes all possible inputs
                        let temp_var = Arc::new(Variable {
                            name: format!("tempSrcAddrFor{}", def.tid),
                            // TODO
                            size: ByteSize::new(8),// var.size,
                            is_temp: true
                        });
                        prog.assign_reg.push((Reg { var: temp_var.clone()}, build_union_of_vars(&input_vars)));
                        prog.assing_deref_reg.push((Reg { var: temp_var.clone()}, expression_to_value_tracking(value)));
                    }
                },
                // AssignReg
                Def::Assign { var, value } => {
                    prog.assign_reg.push((Reg { var: Arc::new(var.clone()) }, expression_to_value_tracking(value)))
                }
            }
        }
    }

    prog.run();
}

fn convert_to_mba_ir() {

}
