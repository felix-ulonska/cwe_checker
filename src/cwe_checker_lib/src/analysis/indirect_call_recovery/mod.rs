//! Indirect Call Target recovery, inspired by BPA.
pub mod json_export;

use std::{
    process::exit,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    ghidra_pcode::ir_passes::IrPass,
    intermediate_representation::{ir_passes::SingleStaticAssigment, Program, Project},
    utils::debug,
};

pub mod memory_block_gen;
use function_taken::get_at_functions;
use itertools::Itertools;
use json_export::export_json;
use memory_block_gen::build_memory_blocks;
use petgraph::algo::connected_components;
use value_tracking::{
    convert_to_ascent_prog::ValueTracking, output::IndirectCalls, slice::slice_program,
    AscentProgram,
};

use super::{
    graph::{get_program_cfg, intraprocedural_cfg::IntraproceduralCfg, Edge, Graph, Node},
    pointer_inference::Config,
};

pub mod function_taken;
pub mod value_tracking;

fn statistics(prog: &Program) {
    let mut indirect_call_counter = 0;
    let mut instr_counter = 0;
    for blk in prog.blocks() {
        let len_defs = blk.defs().collect_vec().len();
        instr_counter += len_defs;
        for call in blk.jmps() {
            if call.is_indirect_call() {
                indirect_call_counter += 1;
            }
        }
    }
    println!("Prog has:\t {} indirect calls", indirect_call_counter);
    println!("\t {} instructions", instr_counter);
}

fn print_benchmark_time(msg: &str) {
    println!(
        "[BENCH], {}: {}",
        msg,
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );
}

// From properties.rs
fn cyclomatic_complexity(graph: &Graph) -> u32 {
    let p = connected_components(graph) as i64;
    let e = graph.edge_count() as i64;
    let n = graph.node_count() as i64;

    let cc = e - n + 2 * p;

    if cc >= 1 && cc < u32::MAX as i64 {
        cc as u32
    } else {
        panic!(
            "CFG with invalid cyclomatic complexity: cc={}, e={}, n={}, p={}",
            cc, e, n, p
        )
    }
}

fn statistics_program(program: &Program) {
    let cfg = get_program_cfg(program);
    println!("Complexity: {}", cyclomatic_complexity(&cfg));
}

// Helper method to drop all structs information that is only constructed to build the ascent_prog
fn build_ascent_prog(
    project: &Project,
    debug_settings: &debug::Settings,
    config: &serde_json::Value,
) -> AscentProgram {
    print!("Pre-SSA|");
    statistics_program(&project.program);
    eprintln!("Starting SSA");
    let mut ssa_program = project.program.clone();
    print_benchmark_time("SSA");

    let config: Config = serde_json::from_value(config.clone()).unwrap();
    let mut pass = <SingleStaticAssigment>::new(&project);
    pass.run(&mut ssa_program);
    print!("Post-SSA|");
    statistics_program(&ssa_program);

    eprintln!("Building Block mem");
    print_benchmark_time("BuildMem");
    let block_memory_model = build_memory_blocks(&ssa_program, &project, &config);
    print_benchmark_time("GetAt");
    let at_functions = get_at_functions(project);

    let mut sliced_program = ssa_program.clone();
    statistics(&ssa_program);
    print_benchmark_time("Slice");
    let rename_table = slice_program(&mut sliced_program, &pass.active_var_at_end_of_block);
    ssa_program = sliced_program;
    print!("Post-Sliced|");
    statistics_program(&ssa_program);
    println!("Sliced:");
    statistics(&ssa_program);

    eprintln!("Start Value Tracking");
    print_benchmark_time("BuildValTracking");
    let mut value_tracking = ValueTracking::new(
        &ssa_program,
        &project,
        &block_memory_model,
        &at_functions,
        &pass.active_var_at_end_of_block,
        &rename_table,
    );
    // Run inside here, to get debug logs. Run outside to drop the helper structs which were used
    // to built the ascent_prog
    value_tracking.convert();
    if debug_settings.should_debug(debug::Stage::ICallRec(true)) {
        value_tracking.run_value_tracking_with_debug();
    }

    let ValueTracking { ascent_prog, .. } = value_tracking;
    ascent_prog
}

/// Needs pointer interference
pub fn run_icall_recovery(
    project: &mut Project,
    debug_settings: &debug::Settings,
    config: &serde_json::Value,
) {
    //value_tracking.run_value_tracking();
    let mut ascent_prog = build_ascent_prog(project, debug_settings, config);
    // Run this, if the ascent_prog is not already run in the build_ascent_prog. This is done to
    // drop all the helper structs to build the prog.
    print_benchmark_time("RunValTracking");
    if !debug_settings.should_debug(debug::Stage::ICallRec(true)) {
        ascent_prog.run();
    }
    print_benchmark_time("Done");
    let indirect_calls = IndirectCalls::from_ascent_prog(&mut ascent_prog);
    indirect_calls.add_to_program(&mut project.program);
    println!("Post");
    println!("{}", ascent_prog.scc_times_summary());
    println!("{}", ascent_prog.relation_sizes_summary());

    if debug_settings.should_debug(debug::Stage::ICallRec(false))
        || debug_settings.should_debug(debug::Stage::ICallRec(true))
    {
        export_json(&project.program);
        exit(0);
    }
}
