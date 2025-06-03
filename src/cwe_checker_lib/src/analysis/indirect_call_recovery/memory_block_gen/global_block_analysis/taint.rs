use ascent::hashbrown::HashSet;

use crate::{
    intermediate_representation::{Def, Sub, Variable},
    prelude::Term,
};

/// Taint Analysis for every input into jump instrucitons, load and store instructions.
pub fn simple_taint<'a>(program: &'a Term<Sub>) -> HashSet<&'a Variable> {
    let mut changes = true;
    let mut taint = HashSet::new();
    let mut checked = HashSet::new();
    for blk in program.blocks() {
        for def in blk.defs() {
            match &def.term {
                crate::intermediate_representation::Def::Load { address, .. } => {
                    taint.extend(address.input_vars());
                }
                crate::intermediate_representation::Def::Store { address, .. } => {
                    taint.extend(address.input_vars());
                }
                _ => (),
            }
        }
    }

    for jmp in program.jmps() {
        match &jmp.term {
            crate::intermediate_representation::Jmp::CBranch {
                target: _target,
                condition,
            } => {
                taint.extend(condition.input_vars());
            }
            _ => (),
        }
    }
    while changes {
        changes = false;

        for blk in program.blocks() {
            for def in blk.defs() {
                if checked.contains(&def.tid) {
                    continue;
                }
                if let Def::Assign { var, value } = &def.term {
                    if taint.contains(&var) {
                        checked.insert(def.tid.clone());
                        changes = true;
                        taint.extend(value.input_vars());
                    }
                }
            }
        }
    }
    taint
}
