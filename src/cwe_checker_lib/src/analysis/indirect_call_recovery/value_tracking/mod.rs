pub mod arc_cache;
pub mod convert_to_ascent_prog;
pub mod output;
pub mod slice;

use std::{fmt::Display, sync::Arc};

use crate::{intermediate_representation::Variable, prelude::Tid};

use ascent::ascent_par;
use itertools::Itertools;

use super::{
    function_taken::Function,
    memory_block_gen::{global_block::Interval, heap_block::HeapBlock, stack_block::StackBlock},
};

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct Blk(Arc<Tid>);

impl Display for Blk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Blk({})", self.0)
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct Sblk(Arc<StackBlock>);
impl Display for Sblk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let min_str = if self.0.min == i64::MIN {
            "-inf"
        } else {
            &self.0.min.to_string()
        };
        let max_str = if self.0.max == i64::MAX {
            "+inf"
        } else {
            &self.0.max.to_string()
        };
        write!(f, "Sblk({}:[{}, {}])", self.0.func_tid, min_str, max_str)
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct Hblk(Arc<HeapBlock>);
impl Display for Hblk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Hblk({})", self.0.id)
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct Gblk(Interval);

impl Display for Gblk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Gblk({})", self.0)
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct Reg {
    var: Arc<Variable>,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum Mloc {
    Gblk(Gblk),
    Sblk(Sblk),
    Hblk(Hblk),
}

impl Display for Mloc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Mloc::Gblk(gblk) => write!(f, "{}", gblk),
            Mloc::Sblk(stack) => write!(f, "{}", stack),
            Mloc::Hblk(hblk) => write!(f, "{}", hblk),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum Loc {
    Mloc(Mloc),
    Reg(Reg),
}

impl Display for Loc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Loc::Reg(reg) => write!(f, "{}", reg.var.name),
            Loc::Mloc(mloc) => write!(f, "{}", mloc),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum Exp {
    Empty,
    Reg(Reg),
    //Mloc(Mloc),
    Deref(Reg),
    RefMLoc(Mloc),
    RefFunc(Arc<Function>),
    Union(Arc<Exp>, Arc<Exp>),
}

impl Display for Exp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Exp::Empty => write!(f, "Empty"),
            Exp::Reg(reg) => write!(f, "{}", reg.var.name),
            //Exp::Mloc(mloc) => write!(f, "{}", mloc),
            Exp::Deref(deref) => write!(f, "*{}", deref.var.name),
            Exp::RefMLoc(ref_mloc) => write!(f, "&{}", ref_mloc),
            Exp::RefFunc(ref_func) => write!(f, "&{}", ref_func),
            Exp::Union(exp1, exp2) => write!(f, "{} U {}", exp1, exp2),
        }
    }
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
            Exp::RefMLoc(mloc) => Loc::Mloc(mloc),
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

//ascent_par! {
ascent_par! {
    //#![measure_rule_times]
    //#![generate_run_timeout]
    // ID is for tracking
    relation assign_reg(Reg, Exp, Arc<Tid>);
    relation assign_mloc(Mloc, Exp, Arc<Tid>);
    relation assing_deref_reg(Reg, Exp, Arc<Tid>);
    relation undeterministic_assign(Reg, Mloc, Exp);
    relation phi(Reg, Reg, Blk);
    relation assign(Loc, Exp, Arc<Tid>);
    relation aloc_val(Loc, Exp);

    // To construct the new phi functions after adding an edge
    // Active vars at end of block
    relation reg_to_block(Reg, Blk);
    // The target of an atfunction
    relation atfunc_to_block(Arc<Function>, Blk);
    // What regs are used for function call
    relation used_func_call(Reg, Blk);

    // From blk to Function
    relation func_call_targets(Blk, Arc<Function>);

    // First is SSA Reg, second is the base reg
    relation base_reg(Reg, Reg);

    // Block at which end is a return statement
    relation block_with_return_of_at_function(Blk, Arc<Function>);

    // Relation with all stack registers
    relation stack_registers(Reg);

    // Maps a block to a function
    relation block_to_func(Blk, Arc<Tid>);

    // Assign is a helper relation: Models if an exp can be assigned to an mloc
    // assign_reg
    assign(reg.into(), exp, id) <-- assign_reg(reg, exp, id);
    // assign_mloc: change for rules
    assign(mloc.into(), exp, id) <-- assign_mloc(mloc, exp, id);
    assign(mloc.into(), exp, id) <-- assing_deref_reg(reg, exp, id), aloc_val(Loc::Reg(reg.clone()), ?Exp::RefMLoc(mloc));


    // v in exp
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
        if let Exp::RefMLoc(mloc) = exp,
        aloc_val(Loc::Mloc(mloc), $v)
    }

    macro vset_deref_ireg($v: ident, $exp: ident) {
        for exp in $exp.to_iter(),
        if let Exp::Deref(reg) = exp,
        aloc_val(Loc::Reg(reg), ?Exp::RefMLoc(mloc)),
        aloc_val(Loc::Mloc(mloc.clone()), $v)
    }

    // AddrMloc and AddrFunc
    aloc_val(loc, mloc) <-- assign(loc, ?mloc@(Exp::RefMLoc(_) | Exp::RefFunc(_)), _);
    // IReg and Mloc
    aloc_val(loc, val) <-- assign(loc, ?Exp::Reg(src_reg), _), aloc_val(Loc::Reg(src_reg.clone()), val);
    aloc_val(loc, val) <-- assign(loc, ?Exp::RefMLoc(src_loc), _), aloc_val(Loc::Mloc(src_loc.clone()), val);
    // DIreg
    aloc_val(loc, val) <--
        assign(loc, ?Exp::Deref(src_reg), _),
        aloc_val(Loc::Reg(src_reg.clone()), ?Exp::RefMLoc(mloc)),
        aloc_val(Loc::Mloc(mloc.clone()), val);

    // Direg but not with refmloc, might be bad?
    aloc_val(loc, val) <--
        assign(loc, ?Exp::Deref(src_reg), _),
        aloc_val(Loc::Reg(src_reg.clone()), ?Exp::RefMLoc(mloc)),
        aloc_val(Loc::Mloc(mloc.clone()), val);

    aloc_val(loc, v) <--
        assign(loc, union, _),
        if let Exp::Union(exp1, exp2) = union,
        vset_mloc_func!(v, union);

    // Vset(ireg)
    aloc_val(loc, v) <--
        assign(loc, union, _),
        if let Exp::Union(exp1, exp2) = union,
        vset_ireg!(v, union);

    // Vset(mloc)
    aloc_val(loc, v) <--
        assign(loc, union, _),
        if let Exp::Union(exp1, exp2) = union,
        vset_mloc!(v, union);

    // Vset(*ireg)
    aloc_val(loc, v) <--
        assign(loc, union, _),
        if let Exp::Union(exp1, exp2) = union,
        vset_deref_ireg!(v, union);

    // UpdMloc
    // Vset(&mloc) and Vset(&func)
    aloc_val(mloc.into(), v) <--
        assing_deref_reg(ireg, exp, _),
        aloc_val(Loc::Reg(ireg.clone()), ?Exp::RefMLoc(mloc)),
        vset_mloc_func!(v, exp);

    // Vset(ireg)
    aloc_val(Loc::Mloc(mloc.clone()), val) <--
        assing_deref_reg(ireg, exp, _),
        aloc_val(Loc::Reg(ireg.clone()), ?Exp::RefMLoc(mloc)),
        vset_ireg!(val, exp);

    // Vset(mloc)
    aloc_val(Loc::Mloc(mloc.clone()), val) <--
        assing_deref_reg(ireg, exp, _),
        aloc_val(Loc::Reg(ireg.clone()), ?Exp::RefMLoc(mloc)),
        vset_mloc!(val, exp);

    // Vset(*ireg)
    aloc_val(Loc::Mloc(mloc.clone()), val) <--
        assing_deref_reg(ireg, exp, _),
        aloc_val(Loc::Reg(ireg.clone()), ?Exp::RefMLoc(mloc)),
        vset_deref_ireg!(val, exp);

    // Phi for no nstack
    aloc_val(Loc::Reg(target_reg.clone()), val) <--
        phi(target_reg, source_reg, target_blk),
        aloc_val(Loc::Reg(source_reg.clone()), val),
        !stack_registers(target_reg);

    // Phi for stack vars
    aloc_val(Loc::Reg(target_reg.clone()), val) <--
        phi(target_reg, source_reg, target_blk),
        aloc_val(Loc::Reg(source_reg.clone()), val),
        stack_registers(target_reg),
        reg_to_block(source_reg, source_blk),
        block_to_func(source_blk, source_fn),
        block_to_func(target_blk, target_fn),
        if let Exp::RefMLoc(Mloc::Sblk(stack_block)) = val,
        if target_fn == source_fn || (stack_block.0.min < 0 && stack_block.0.func_tid == **source_fn); 

    func_call_targets(blk, func) <--
        aloc_val(?Loc::Reg(ireg), ?ref_func@Exp::RefFunc(func)),
        used_func_call(ireg, blk);


    macro is_same_base_reg($reg1: expr, $reg2: expr) {
        //let src_base_reg = $reg1.var.name.split(SPLIT_SYMBOL).collect_vec()[0],
        //let target_base_reg = $reg2.var.name.split(SPLIT_SYMBOL).collect_vec()[0],
        base_reg($reg1, base_reg_1),
        base_reg($reg2, base_reg_2),
        if base_reg_1 == base_reg_2
    }

    // If, func to callsite, then create phi instruction
    phi(callee_reg, caller_reg, callee_blk) <--
        func_call_targets(caller_blk, func),
        atfunc_to_block(func, callee_blk),
        reg_to_block(caller_reg, caller_blk),
        reg_to_block(callee_reg, callee_blk),
        is_same_base_reg!(caller_reg, callee_reg);

    phi(target_reg, callee_reg, after_call_blk) <--
        phi(target_reg, caller_reg, after_call_blk),
        func_call_targets(caller_blk, callee_func),
        block_with_return_of_at_function(blk_in_callee, callee_func),
        reg_to_block(caller_reg, caller_blk),
        reg_to_block(callee_reg, blk_in_callee),
        is_same_base_reg!(target_reg, callee_reg);
}

/// Converts an Vec<Variable> to Tree like Exp expressions where the expressions is a union of all
/// possible vars
fn build_union_of_vars(vars: &Vec<&Variable>) -> Exp {
    let mut exps = vars
        .into_iter()
        .map(|var| {
            Exp::Reg(Reg {
                var: Arc::new((*var).clone()),
            })
        })
        .collect_vec();

    if exps.len() == 0 {
        return Exp::Empty;
    }

    // Terminates as each iter, 2 pops and 1 add.
    while exps.len() > 1 {
        let exp_first = exps.pop().unwrap();
        let exp_second = exps.pop().unwrap();
        exps.push(Exp::Union(Arc::new(exp_first), Arc::new(exp_second)));
    }

    exps.pop()
        .expect("A vlaue should exist, the check is right bevor this line")
}

fn build_union_of_vars_as_deref(vars: &Vec<&Variable>) -> Exp {
    let mut exps = vars
        .into_iter()
        .map(|var| {
            Exp::Deref(Reg {
                var: Arc::new((*var).clone()),
            })
        })
        .collect_vec();

    if exps.len() == 0 {
        return Exp::Empty;
    }

    // Terminates as each iter, 2 pops and 1 add.
    while exps.len() > 1 {
        let exp_first = exps.pop().unwrap();
        let exp_second = exps.pop().unwrap();
        exps.push(Exp::Union(Arc::new(exp_first), Arc::new(exp_second)));
    }

    exps.pop()
        .expect("A vlaue should exist, the check is right bevor this line")
}
