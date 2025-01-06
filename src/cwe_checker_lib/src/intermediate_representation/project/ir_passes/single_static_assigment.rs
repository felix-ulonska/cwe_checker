use std::collections::{HashMap, HashSet};

use itertools::Itertools;
use petgraph::visit::EdgeRef;

use crate::{analysis::graph::{get_program_cfg, Node}, intermediate_representation::{Def, Expression, Project, Variable}, prelude::{Term, Tid}, utils::debug::IrForm};

use super::{prelude::{LogMessage, Program}, IrPass};

/// Computes register-SSA with a really crude approach 
/// For each register, we add a phi instruction at the start of each block. This is the opposite of
/// memory efficency.
pub struct SingleStaticAssigment {
    register_vars: Vec<Variable>,
}

impl SingleStaticAssigment {
    fn get_used_register(&self, program: &Program) -> Vec<Variable> {
        // We need to aggregate all names, as we do the really crude method!
        let mut var_names = HashSet::new();
        for sub in &program.subs {
            for blks in sub.1.blocks() {
                for defs in blks.defs() {
                    match &defs.term {
                        Def::Load { var, .. } | Def::Assign { var, .. } => var_names.insert(var.name.clone()),
                        Def::Store { .. } => false,
                    };
                }
            }
        }

        let mut used_register_vars = Vec::new();

        for register_var in &self.register_vars {
            if var_names.contains(&register_var.name) {
                used_register_vars.push(register_var.clone());
            }
        }
        used_register_vars
    }
}

fn get_incoming_edges_for_each_blk(program: &Program) -> HashMap::<String, Vec<String>> {
    let mut cfg = get_program_cfg(program);
    cfg.reverse();
    // Saves the incoming edges for each block
    let mut incoming_edge_for_each_block = HashMap::<String, Vec<String>>::new();
    for block in program.blocks() {
        incoming_edge_for_each_block.insert(block.tid.to_string(), vec![]);
    }

    for node in cfg.node_indices(){
        if let Node::BlkStart(_, _) = cfg[node] {
            let edges = cfg.edges(node);
            for edge in edges {
                let target_node = edge.target();
                if let Some(blk) = cfg[target_node].try_get_block(){
                    let incoming_edges = incoming_edge_for_each_block
                        .get_mut(&cfg[edge.source()].get_block().tid.to_string())
                        .expect("Blk had no key in incoming_edge_for_each_block, should never happen");
                    incoming_edges.push(blk.tid.to_string());
                }
            }
        }
    }

    incoming_edge_for_each_block
}

fn rename_all_vars_and_add_empty_phi_fn(program: &mut Program, used_register_vars: &Vec<Variable>) -> HashMap<String, HashMap::<String, i64>> {
    let mut active_var_at_end_of_block = HashMap::<String, HashMap::<String, i64>>::new();
    let mut active_indices = HashMap::<String, i64>::new();
    for var in used_register_vars {
        active_indices.insert(var.name.clone(), 0);
    }
    for block in program.blocks_mut() {
        let mut phi_instruction_at_begin = used_register_vars
            .iter()
            .map(|var| {
                let new_var_index = active_indices[&var.name] + 1;
                active_indices.insert(var.name.clone(), new_var_index);
                Term {
                    tid: Tid::new_phi(&block.tid, &var.name),
                    term: Def::Assign{
                        var: Variable{
                             name: format!("{}_{}", &var.name, new_var_index),
                             size: var.size,
                             is_temp: false,
                        },
                        // TODO fill in
                        value: Expression::Phi(vec![])
                    },
                }
            }).collect_vec();
        phi_instruction_at_begin.extend(block.defs.clone());
        block.defs = phi_instruction_at_begin;

        for def in &mut block.defs {
            for var in used_register_vars {
                def.substitute_input_var(&var, &Expression::Var(Variable {
                    name: format!("{}_{}", var.name, active_indices[&var.name]),
                    size: var.size,
                    is_temp: false,
                }))
            }
            match &mut def.term {
                Def::Assign { var, .. } | Def::Load { var, .. } => {
                    if used_register_vars.contains(var) {
                        let new_var_index = active_indices[&var.name] + 1;
                        active_indices.insert(var.name.clone(), new_var_index);
                        var.name = format!("{}_{}", var.name, new_var_index).to_owned();
                    }
                }
                _ => (),
            }
        }

        for jmp in &mut block.jmps_mut() {
            for var in used_register_vars {
                jmp.term.substitute_input_var(&var, &Expression::Var(Variable {
                    name: format!("{}_{}", var.name, active_indices[&var.name]),
                    size: var.size,
                    is_temp: false,
                }))
            }
        }

        let mut active_vars = vec![];
        for var in used_register_vars {
            active_vars.push(Variable {
                name: format!("{}_{}", var.name, active_indices[&var.name]),
                size: var.size,
                is_temp: false,
            });
        }

        active_var_at_end_of_block.insert(block.tid.to_string(), active_indices.clone());
    }
    active_var_at_end_of_block
}

fn fix_phi_functions(program: &mut Program, incoming_edge_for_each_block: HashMap::<String,Vec<String>>, active_var_at_end_of_block: HashMap<String, HashMap::<String, i64>>) {
    for block in program.blocks_mut() {
        for incoming_edge_name in &incoming_edge_for_each_block[&block.tid.to_string()] {
            for def in block.defs_mut() {
                if let Term { term: Def::Assign { var,  value: Expression::Phi(inputs) }, .. } = def {
                    let original_name = var.name.split("_").take(1).collect_vec()[0];
                    println!("Incoming name: {};{}", &incoming_edge_name.clone(), original_name);
                    inputs.push(Variable {
                        name: format!("{}_{}", original_name, active_var_at_end_of_block[&incoming_edge_name.clone()][original_name]),
                        size: var.size,
                        is_temp: false
                    })
                } 
            }
        }
    }
}

impl IrPass for SingleStaticAssigment {
    const NAME: &'static str = "SingleStaticAssigment";

    const DBG_IR_FORM: super::prelude::debug::IrForm = IrForm::SingleStaticAssigment;

    type Input = Program;
    type ConstructionInput = Project;

    fn new(construction_input: &Self::ConstructionInput) -> Self {
        return SingleStaticAssigment {
            register_vars: construction_input.register_set.iter().map(|var| var.clone()).clone().collect_vec()
        }
    }


    fn run(&mut self, mut program: &mut Self::Input) -> Vec<super::prelude::LogMessage> {
        let mut logs: Vec<LogMessage> = vec![];

        let used_register_vars = self.get_used_register(&program);

        logs.push(
            LogMessage::new_info(
                format!("Found following var names {}", itertools::join(&used_register_vars, ","))
            )
        );

        let incoming_edge_for_each_block = get_incoming_edges_for_each_blk(&program);

        let active_var_at_end_of_block = rename_all_vars_and_add_empty_phi_fn(&mut program, &used_register_vars);

        fix_phi_functions(program, incoming_edge_for_each_block, active_var_at_end_of_block);

        logs
    }

    fn assert_postconditions(_construction_input: &Self::ConstructionInput, _program: &Self::Input) {
        todo!()
    }
}

    #[cfg(test)]
    mod tests {
        use project::SingleStaticAssigment;

    use crate::expr;
    use crate::{defs, intermediate_representation::*, run_ir_pass, utils::debug};
    use crate::ghidra_pcode::ir_passes::IrPass;

    /// we built this code:
    /// x = 1; // blk1
    /// y = 2;
    /// if (x > 1) { // blk2
    ///     x = y;
    /// }
    /// y = 1 // blk3
    #[test]
    fn test_ssa() {
        let mut project = Project::mock_x64();
        let mut blk1 = Blk::default();
        blk1.defs = defs![
            "tid_1: RAX:8 = 0x1:1",
            "tid_2: RCX:8 = 0x2:1"
        ];
        let mut blk1 = Term {
            tid: Tid::new("blk_1"),
            term: blk1
        };

        let mut blk2 = Blk::default();
        blk2.defs = defs![
            "tid_3: RAX:8 = RCX:8"
        ];

        let mut blk3 = Blk::default();
        blk3.defs = defs![
            "tid_4: RCX:8 = 0x1:1"
        ];
        let blk3 = Term {
            tid: Tid::new("blk_3"),
            term: blk3
        };

        let if_jmp = Jmp::CBranch {
            target: Tid::new("blk_2").clone(),
            condition: expr!("RAX:8 - 0x1:1"),
        };
        let if_jmp = Term {
            tid: Tid::new("foo_jmp_if"),
            term: if_jmp,
        };
        let else_jmp = Jmp::Branch(Tid::new(blk3.tid.clone()));
        let else_jmp = Term {
            tid: Tid::new("foo_jmp_else"),
            term: else_jmp,
        };
        blk1.term.add_jumps(vec![if_jmp, else_jmp]);
        let jmp_to_3 = Jmp::Branch(Tid::new(blk3.tid.clone()));
        let blk1_jmp = Term {
            tid: Tid::new("foo_jmp_else_2"),
            term: jmp_to_3,
        };
        blk2.add_jumps(vec![blk1_jmp]);
        let blk2 = Term {
            tid: Tid::new("blk_2"),
            term: blk2
        };

        let mut sub = Sub::mock("main");
        sub.term.blocks.push(blk1);
        sub.term.blocks.push(blk2);
        sub.term.blocks.push(blk3);
        project.program.subs.insert(sub.tid.clone(), sub);

        for blk in project.program.blocks() {
            println!("{}", blk);
        }
        println!("====POST====");
        let mut logs = vec![];
        run_ir_pass![
            project.program,
            project,
            SingleStaticAssigment,
            logs,
            debug::Settings::default()
        ];

        for log in logs {
            println!("{}", log);
        }

        for blk in project.program.blocks() {
            println!("{}", blk);
        }


        //assert_eq!(block.term.defs, result_defs);
    }
}
