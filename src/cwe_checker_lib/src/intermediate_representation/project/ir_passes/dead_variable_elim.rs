use super::prelude::*;

use crate::analysis::graph::get_program_cfg;
use crate::intermediate_representation::Variable;

use std::collections::BTreeSet;

mod fixpoint_computation;

/// Intraprocedural kill-gen DFA that computes the variables that are alive at
/// any given point within the program.
///
/// **Def.** _alive_: There exists some path from the point `l` to the end of
/// the function where the variable may be read before it is overwritten.
///
/// **Def.** _dead_: A variable is dead at `l` if it is not alive.
///
/// All assignments where the assigned variable is dead 'after' the assignment
/// are removed.
///
/// **Function call handling**: At call sites, all physical registers are
/// considered alive. This is since the called function might read them.
// TODO: Could we limit this to registers that are used for argument passing?
///
/// **Return site handling aka. initial state**: At return sites or other dead
/// ends in the intraprocedural CFG, we assume all physical registers are
/// alive. This is since the caller might read them.
// TODO: Could we limit this to callee-saved registers and registers used for
// passing the return value?
///
/// Note: Temporary registers are assumed to be incaccesible to callees and
/// the caller.
///
/// Note: One might think that a compiler would not produce such unnecessary
/// assignments. That's hopefully true - but the conversion to Pcode produces
/// lots of those assignments by expanding complex instructions.
///
/// Note: Propagating input expressions before running this pass allows more
/// assignments to be eliminated.
pub struct DeadVariableElimPass {
    all_phys_registers: BTreeSet<Variable>,
}

impl IrPass for DeadVariableElimPass {
    const NAME: &'static str = "DeadVariableEliminationPass";
    const DBG_IR_FORM: debug::IrForm = debug::IrForm::DeadVariablesElimed;

    type Input = Program;
    type ConstructionInput = BTreeSet<Variable>;

    fn new(all_phys_registers: &Self::ConstructionInput) -> Self {
        Self {
            all_phys_registers: all_phys_registers.clone(),
        }
    }

    fn run(&mut self, program: &mut Self::Input) -> Vec<LogMessage> {
        let mut graph = get_program_cfg(program);
        graph.reverse();
        let all_variables = program.all_variables();
        let all_variables_ref = all_variables.iter().collect::<BTreeSet<&Variable>>();

        // Maps block TIDs to the set of variables that are alive after
        // the execution of the BB.
        let alive_vars_map = fixpoint_computation::compute_alive_vars(
            &all_variables,
            &self.all_phys_registers,
            &graph,
        );

        // Propagate the block-end information through the block and remove
        // dead assignment along the way.
        for b in program.blocks_mut() {
            fixpoint_computation::remove_dead_var_assignments_of_block(
                b,
                &alive_vars_map,
                &all_variables_ref,
            );
        }

        Vec::new()
    }

    fn assert_postconditions(
        _all_phys_registers: &Self::ConstructionInput,
        _program: &Self::Input,
    ) {
    }
}

// TODO: Fix tests.
/*
#[cfg(test)]
mod tests {
    use super::*;
    use crate::defs;

    #[test]
    fn dead_assignment_removal() {
        let defs = defs![
            "def_1: B:8 = A:8",
            "def_2: C:8 = B:8",
            "def_3: RAX:8 = C:8",
            "def_4: RAX:8 = B:8",
            "def_5: RBX:8 = C:8",
            "def_6: B:8 = A:8",
            "def_7: C:8 = B:8"
        ];
        let block = Term {
            tid: Tid::new("block"),
            term: Blk {
                defs: defs,
                jmps: Vec::new(),
                indirect_jmp_targets: Vec::new(),
            },
        };
        let sub = Term {
            tid: Tid::new("sub"),
            term: Sub {
                name: "sub".to_string(),
                blocks: vec![block],
                calling_convention: None,
            },
        };
        let mut project = Project::mock_x64();
        project.program.term.subs.insert(sub.tid.clone(), sub);
        remove_dead_var_assignments(&mut project);

        let cleaned_defs = defs![
            "def_1: B:8 = A:8",
            "def_2: C:8 = B:8",
            "def_4: RAX:8 = B:8",
            "def_5: RBX:8 = C:8"
        ];
        assert_eq!(
            &project.program.term.subs[&Tid::new("sub")].term.blocks[0]
                .term
                .defs,
            &cleaned_defs
        );
    }
}
*/
