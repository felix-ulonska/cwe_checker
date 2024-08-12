//! Microbenchmarks for the `cwe_checker`.
//!
//! This module contains microbenchmarks for various steps in the `cwe_checker`.
//! Currently there are benchmarks for the following steps:
//!
//! - interprocedural CFG construction,
//! - individual IR passes,
//! - function signatures analysis,
//! - pointer inference,
//! - string abstractions,
//! - individual checkers.
// TODO:
// - call graph
//!
//! All benchmarks are executed on the following input programs:
//!
//! - ls,
//! - netfs.ko,
//!
//! for the following architectures:
//!
//! - amd64,
//! - arm64,
//! - armel,
//! - armhf,
//! - hppa,
//! - m68k,
//! - mipsel,
//! - mips64el,
//! - ppc64el,
//! - riscv64,
//! - sh4,
//! - sparc64,
//! - x86.
//!
//! Inputs are stored in the `benches/_data/` directory. We provide
//! json-serialized pcode projects (i.e., output of the Ghidra plugin) and
//! binaries. The pcode projects are included for the following reasons:
//!
//! - not requiring a Ghidra installation on the benchmarking system,
//! - avoid that changes in Ghidra version influence the benchmark results,
//! - result of the Ghidra analysis is non-deterministic,
//! - reduce the time it takes to run the benchmarks.
//!
//! # Getting the Inputs
//!
//! The input programs are not included in this repository. Before you can run
//! the benchmarks you need to download them.
//!
//TODO: Update
//! ```
//! $ cd benches/_data/
//! $ wget https://valentinobst.de/34defc254cb6f45ef074431465b7ecc614a6a87e97b13a5c7d0a113e4ed67c6b/cwe_checker_benches.tar.gz
//! $ sha256sum cwe_checker_benches.tar.gz
//! 34defc254cb6f45ef074431465b7ecc614a6a87e97b13a5c7d0a113e4ed67c6b  cwe_checker_benches.tar.gz
//! $ tar xf cwe_checker_benches.tar.gz
//! $ rm cwe_checker_benches.tar.gz
//! ```
//!
//! # Running the Benchmarks
//!
//! If you submit a PR that makes changes which might impact performance you are
//! encouraged to run these benchmarks. In this case, please report the relevant
//! changes between the current master and your code in the PR description.
//!
//! Let's assume you made a change that speeds up the CFG generation. First run
//! the benchmarks on the current master and save the result:
//!
//! ```
//! $ git checkout master
//! $ cargo bench --bench "benchmarks" -- --save-baseline master cfg_construction
//! ```
//!
//! Then, checkout your feature branch and compare to the current master:
//!
//! ```
//! $ git checkout my_awesome_fix
//! $ cargo bench --bench "benchmarks" -- --verbose --baseline master cfg_construction
//! ```
//!
//! In the PR, you can either copy-paste the console output, or, even better,
//! attach the relevant parts of the html report (generated under
//! `target/criterion`).
//!
//! If your PR adds code that is not currently benchmarked, you are encouraged
//! to add a benchmark for it to this module.
//!
//! In general, absolute benchmark results are always tied to the system that
//! they were measured on. Thus, it only makes sense to report relative results
//! in your PR. To ensure that results are comparable between runs it may help
//! to follow the advice given below:
//!
//! - ensure that the system is calm, i.e., use a dedicated system and try
//!   to shut off as many background processes as possible,
//! - set adaptive CPU frequency scaling and cooling profiles to
//!   'performance' in the OS and UEFI firmware settings,
//! - connect laptops to the power supply.

use std::fs;
use std::io::Read;
use std::iter;
use std::time;

use criterion::{
    black_box, criterion_group, criterion_main,
    measurement::{Measurement, WallTime},
    BatchSize, BenchmarkGroup, BenchmarkId, Criterion, SamplingMode, Throughput,
};

use cwe_checker_lib::analysis::graph;
use cwe_checker_lib::intermediate_representation::{Project, RuntimeMemoryImage};
use cwe_checker_lib::pipeline::AnalysisResults;
use cwe_checker_lib::utils;

mod inputs {
    //! Constants used to access inputs stored in `benches/_data`.

    pub const LS_PCODE_PROJECTS: [&str; 12] = [
        "amd64-ls_CB30D69B24245BF2",
        "arm64-ls_8D0A90D5AA1F9151",
        "armel-ls_400B36192085C142",
        "armhf-ls_1CE9F5077E5469C9",
        "hppa-ls_CB00BEAB0E4CF46F",
        "m68k-ls_3A787F3CDAC20FB7",
        "mipsel-ls_7CB1427659E706FB",
        "ppc64el-ls_0507CC2232E82FA9",
        "riscv64-ls_5E6CB71A0BF3A32C",
        "sh4-ls_A8CBD4851F3DF96D",
        "sparc64-ls_26C5102B99E82FE4",
        "x86-ls_AFE4E5F03F4CF0F7",
    ];

    pub const NETFS_PCODE_PROJECTS: [&str; 12] = [
        "amd64-netfs.ko_2968775E85859742",
        "arm64-netfs.ko_91816E1342973AFA",
        "armhf-netfs.ko_B7FA86FF57F64C18",
        "hppa-netfs.ko_C8E221F0DBDE60EB",
        "m68k-netfs.ko_6CD482FD644FED53",
        "mips32r2el-netfs.ko_6DF4CC2FD1E91EDC",
        "mips64r2el-netfs.ko_5331834BF22142BD",
        "powerpc64le-netfs.ko_332ECD2BFBEE0616",
        "riscv64-netfs.ko_F705F80482B21FC4",
        "sh4-netfs.ko_EE85BEDC21B7A178",
        "sparc64-netfs.ko_0E6844B4CE53C1E3",
        "x86-netfs.ko_70E21F23852A0A0B",
    ];

    pub const LS_BINARIES: [&str; 12] = [
        "amd64-ls",
        "arm64-ls",
        "armel-ls",
        "armhf-ls",
        "hppa-ls",
        "m68k-ls",
        "mipsel-ls",
        "ppc64el-ls",
        "riscv64-ls",
        "sh4-ls",
        "sparc64-ls",
        "x86-ls",
    ];

    pub const NETFS_BINARIES: [&str; 12] = [
        "amd64-netfs.ko",
        "arm64-netfs.ko",
        "armhf-netfs.ko",
        "hppa-netfs.ko",
        "m68k-netfs.ko",
        "mips32r2el-netfs.ko",
        "mips64r2el-netfs.ko",
        "powerpc64le-netfs.ko",
        "riscv64-netfs.ko",
        "sh4-netfs.ko",
        "sparc64-netfs.ko",
        "x86-netfs.ko",
    ];
}

mod helpers {
    //! Helpers to get inputs and configurations.

    use super::*;
    use cwe_checker_lib::utils::{debug, log::WithLogs};

    const PREFIX: &str = "benches/_data/";
    const CONFIG: &str = "../config.json";

    /// Returns the unoptimized IR project for the given Ghidra plugin output
    /// and corresponding binary.
    pub fn get_project_and_binary(pcode_project_json: &str, binary: &str) -> (Project, Vec<u8>) {
        let pcode_project = fs::read_to_string(format!("{}{}", PREFIX, pcode_project_json))
            .expect("Could not read pcode project.");
        let pcode_project =
            serde_json::from_str(&pcode_project).expect("Could not deserialize pcode project.");
        let binary: Vec<u8> = fs::File::open(format!("{}{}", PREFIX, binary))
            .expect("Could not read binary.")
            .bytes()
            .map(|x| x.unwrap())
            .collect();
        let mut project = utils::ghidra::parse_pcode_project_to_ir_project(
            pcode_project,
            &binary,
            &None,
            &get_debug_settings(),
        )
        .expect("Could not translate Pcode project to IR project.")
        .into_object();
        let mut runtime_memory_image =
            RuntimeMemoryImage::new(&binary).expect("Could not generate RuntimeMemoryImage.");
        if project.program.term.address_base_offset != 0 {
            runtime_memory_image.add_global_memory_offset(project.program.term.address_base_offset);
        }
        project.runtime_memory_image = runtime_memory_image;

        (project, binary)
    }

    /// Returns the checker configuration.
    pub fn get_config() -> serde_json::Value {
        let config_file = std::fs::read_to_string(CONFIG).expect("Could not read config file.");

        serde_json::from_str(&config_file).expect("Could not deserialize config file.")
    }

    /// Convenience wrapper around [`get_project_and_binary`] that just returns
    /// the IR Project.
    pub fn get_project(pcode_project_json: &str, binary: &str) -> Project {
        get_project_and_binary(pcode_project_json, binary).0
    }

    /// Convenience wrapper to construct [`debug::Settings`].
    pub fn get_debug_settings() -> debug::Settings {
        debug::Settings::default()
    }

    /// Optimizes the given IR project.
    pub fn into_optimized_project(project: Project) -> Project {
        let mut tmp = WithLogs::new(project, vec![]);
        tmp.optimize(&get_debug_settings());
        tmp.into_object()
    }
}

mod checkers {
    //! Benchmarks for individual checkers.

    use super::helpers::*;
    use super::inputs::*;
    use super::*;
    use cwe_checker_lib::checkers::*;

    fn helper_bench_checker<T>(
        checker: &cwe_checker_lib::CweModule,
        group: BenchmarkGroup<T>,
        is_lkm: bool,
    ) where
        T: Measurement,
    {
        let config = get_config();
        let bench_with_input_loop =
            |pcode_projects: &[&str], binaries: &[&str], mut group: BenchmarkGroup<T>| {
                for (pcode_project_json, binary) in iter::zip(pcode_projects, binaries) {
                    let (project, binary) = get_project_and_binary(pcode_project_json, binary);
                    let project = into_optimized_project(project);
                    let cfg = graph::get_program_cfg(&project.program);

                    let analysis_results = AnalysisResults::new(&binary, &cfg, &project);

                    let function_signatures =
                        analysis_results.compute_function_signatures().into_object();
                    let analysis_results =
                        analysis_results.with_function_signatures(Some(&function_signatures));

                    let pi_result =
                        analysis_results.compute_pointer_inference(&config["Memory"], false);
                    let analysis_results =
                        analysis_results.with_pointer_inference(Some(&pi_result));

                    // Only CWE78 needs string abstractions and we do not
                    // benchmark this checker.

                    group.throughput(Throughput::Elements(cfg.edge_count() as u64));
                    group.bench_with_input(
                        BenchmarkId::from_parameter(pcode_project_json),
                        &analysis_results,
                        |b, analysis_results| {
                            b.iter_with_large_drop(|| {
                                (checker.run)(analysis_results, &config[&checker.name])
                            })
                        },
                    );
                }

                group.finish();
            };

        if is_lkm {
            bench_with_input_loop(&NETFS_PCODE_PROJECTS, &NETFS_BINARIES, group);
        } else {
            bench_with_input_loop(&LS_PCODE_PROJECTS, &LS_BINARIES, group);
        }
    }

    macro_rules! bench_checker {
        ($c:ident) => {
            bench_checker!(name = $c; samples = 100; time = 10);
        };
        (name = $c:ident; samples = $s:expr; time = $t:expr) => {
            ::paste::paste! {
                pub fn [<bench_ $c>](c: &mut Criterion) {
                    let mut group_ls = c.benchmark_group(stringify!([<ls_ $c>]));
                    group_ls
                        .sample_size($s)
                        .warm_up_time(time::Duration::new(($t as u64).checked_div(2).unwrap(), 0))
                        .measurement_time(time::Duration::new($t, 0));
                    helper_bench_checker(&$c::CWE_MODULE, group_ls, false);

                    if MODULES_LKM.contains(
                        &["CWE", stringify!($c).split("_").last().unwrap()]
                            .concat()
                            .as_str()
                        )
                    {
                        let mut group_netfs = c.benchmark_group(stringify!([<netfs_ $c>]));
                        group_netfs
                            .sample_size($s)
                            .warm_up_time(time::Duration::new(($t as u64).checked_div(2).unwrap(), 0))
                            .measurement_time(time::Duration::new($t, 0));
                        helper_bench_checker(&$c::CWE_MODULE, group_netfs, true);
                    }
                }
            }
        };
    }

    bench_checker!(
        name = cwe_119;
        samples = 10;
        time = 20
    );
    bench_checker!(cwe_134);
    bench_checker!(cwe_190);
    bench_checker!(cwe_215);
    bench_checker!(cwe_243);
    bench_checker!(
        name = cwe_252;
        samples = 10;
        time = 20
    );
    bench_checker!(
        name = cwe_332;
        samples = 1000;
        time = 10
    );
    bench_checker!(
        name = cwe_337;
        samples = 1000;
        time = 10
    );
    bench_checker!(cwe_367);
    bench_checker!(
        name = cwe_416;
        samples = 10;
        time = 20
    );
    bench_checker!(cwe_426);
    bench_checker!(cwe_467);
    bench_checker!(
        name = cwe_476;
        samples = 10;
        time = 20
    );
    bench_checker!(
        name = cwe_560;
        samples = 1000;
        time = 10
    );
    bench_checker!(cwe_676);
    bench_checker!(cwe_782);
    bench_checker!(cwe_789);
}

mod core_analyses {
    //! Benchmarks for function signatures, pointer inference and string
    //! abstractions.

    use super::helpers::*;
    use super::inputs::*;
    use super::*;

    pub fn bench_function_signatures(c: &mut Criterion) {
        let bench_with_input_loop =
            |pcode_projects: &[&str], binaries: &[&str], mut group: BenchmarkGroup<WallTime>| {
                for (pcode_project_json, binary) in iter::zip(pcode_projects, binaries) {
                    let (project, binary) = get_project_and_binary(pcode_project_json, binary);
                    let project = into_optimized_project(project);
                    let cfg = graph::get_program_cfg(&project.program);

                    let analysis_results = AnalysisResults::new(&binary, &cfg, &project);

                    group.throughput(Throughput::Elements(cfg.edge_count() as u64));
                    group.bench_with_input(
                        BenchmarkId::from_parameter(pcode_project_json),
                        &analysis_results,
                        |b, analysis_results| {
                            b.iter_with_large_drop(|| {
                                analysis_results.compute_function_signatures()
                            })
                        },
                    );
                }

                group.finish();
            };

        let mut group_ls = c.benchmark_group("ls_function_signatures");
        group_ls
            .sampling_mode(SamplingMode::Flat)
            .warm_up_time(time::Duration::new(60, 0))
            .measurement_time(time::Duration::new(120, 0));
        bench_with_input_loop(&LS_PCODE_PROJECTS, &LS_BINARIES, group_ls);

        let mut group_netfs = c.benchmark_group("netfs_function_signatures");
        group_netfs
            .sampling_mode(SamplingMode::Flat)
            .warm_up_time(time::Duration::new(30, 0))
            .measurement_time(time::Duration::new(60, 0));
        bench_with_input_loop(&NETFS_PCODE_PROJECTS, &NETFS_BINARIES, group_netfs);
    }

    pub fn bench_pi(c: &mut Criterion) {
        let bench_with_input_loop =
            |pcode_projects: &[&str], binaries: &[&str], mut group: BenchmarkGroup<WallTime>| {
                let config = get_config();
                for (pcode_project_json, binary) in iter::zip(pcode_projects, binaries) {
                    let (project, binary) = get_project_and_binary(pcode_project_json, binary);
                    let project = into_optimized_project(project);
                    let cfg = graph::get_program_cfg(&project.program);

                    let analysis_results = AnalysisResults::new(&binary, &cfg, &project);

                    let function_signatures =
                        analysis_results.compute_function_signatures().into_object();
                    let analysis_results =
                        analysis_results.with_function_signatures(Some(&function_signatures));

                    group.throughput(Throughput::Elements(cfg.edge_count() as u64));
                    // FIXME: This should be `bench_with_input`, workaround due
                    // to lifetime hell.
                    group.bench_function(BenchmarkId::new("pi", pcode_project_json), |b| {
                        b.iter_with_large_drop(|| {
                            analysis_results
                                .compute_pointer_inference(&config["Memory"], black_box(false))
                        })
                    });
                }

                group.finish();
            };

        let mut group_ls = c.benchmark_group("ls_pi");
        group_ls
            .sampling_mode(SamplingMode::Flat)
            .warm_up_time(time::Duration::new(30, 0))
            .measurement_time(time::Duration::new(60, 0));
        bench_with_input_loop(&LS_PCODE_PROJECTS, &LS_BINARIES, group_ls);

        let mut group_netfs = c.benchmark_group("netfs_pi");
        group_netfs
            .sampling_mode(SamplingMode::Flat)
            .warm_up_time(time::Duration::new(20, 0))
            .measurement_time(time::Duration::new(30, 0));
        bench_with_input_loop(&NETFS_PCODE_PROJECTS, &NETFS_BINARIES, group_netfs);
    }

    pub fn bench_string_abstractions(c: &mut Criterion) {
        let bench_with_input_loop =
            |pcode_projects: &[&str], binaries: &[&str], mut group: BenchmarkGroup<WallTime>| {
                let config = get_config();
                for (pcode_project_json, binary) in iter::zip(pcode_projects, binaries) {
                    let (project, binary) = get_project_and_binary(pcode_project_json, binary);
                    let project = into_optimized_project(project);
                    let cfg = graph::get_program_cfg(&project.program);

                    let analysis_results = AnalysisResults::new(&binary, &cfg, &project);

                    let function_signatures =
                        analysis_results.compute_function_signatures().into_object();
                    let analysis_results =
                        analysis_results.with_function_signatures(Some(&function_signatures));

                    let pi_result =
                        analysis_results.compute_pointer_inference(&config["Memory"], false);
                    let analysis_results =
                        analysis_results.with_pointer_inference(Some(&pi_result));

                    group.throughput(Throughput::Elements(cfg.edge_count() as u64));
                    // FIXME: This should be `bench_with_input`, workaround due
                    // to lifetime hell.
                    group.bench_function(
                        BenchmarkId::new("string_abstractions", pcode_project_json),
                        |b| {
                            b.iter_with_large_drop(|| {
                                analysis_results.compute_string_abstraction(
                                    &config["StringAbstraction"],
                                    black_box(Some(&pi_result)),
                                )
                            })
                        },
                    );
                }

                group.finish();
            };

        let mut group_ls = c.benchmark_group("ls_string_abstractions");
        group_ls
            .warm_up_time(time::Duration::new(30, 0))
            .measurement_time(time::Duration::new(60, 0));
        bench_with_input_loop(&LS_PCODE_PROJECTS, &LS_BINARIES, group_ls);

        let mut group_netfs = c.benchmark_group("netfs_string_abstractions");
        group_netfs
            .warm_up_time(time::Duration::new(10, 0))
            .measurement_time(time::Duration::new(30, 0));
        bench_with_input_loop(&NETFS_PCODE_PROJECTS, &NETFS_BINARIES, group_netfs);
    }
}

mod optimization {
    //! Benchmarks for individual optimization passes.

    use super::helpers::*;
    use super::inputs::*;
    use super::*;
    use cwe_checker_lib::intermediate_representation::ir_passes::*;

    fn helper_bench_optimization<F, G, T: Measurement, U>(
        pre_passes: F,
        pass: G,
        mut group: BenchmarkGroup<T>,
        is_lkm: bool,
    ) where
        F: Fn(&mut Project),
        G: Fn(&mut Project) -> U,
    {
        let bench_with_input_loop = |pcode_projects: &[&str], binaries: &[&str]| {
            for (pcode_project_json, binary) in iter::zip(pcode_projects, binaries) {
                let mut project = get_project(pcode_project_json, binary);

                pre_passes(&mut project);

                group.bench_with_input(
                    BenchmarkId::from_parameter(pcode_project_json),
                    &project,
                    |b, project| {
                        b.iter_batched_ref(
                            || project.clone(),
                            |project| pass(project),
                            BatchSize::LargeInput,
                        )
                    },
                );
            }

            group.finish();
        };

        if is_lkm {
            bench_with_input_loop(&NETFS_PCODE_PROJECTS, &NETFS_BINARIES);
        } else {
            bench_with_input_loop(&LS_PCODE_PROJECTS, &LS_BINARIES);
        }
    }

    macro_rules! bench_pass {
        (name = $p:ident; pre_passes = $pre:expr; pass = $pass:expr) => {
            bench_pass!(
                name = $p;
                pre_passes = $pre;
                pass = $pass;
                samples = 10;
                time = 30
            );
        };
        (name = $p:ident; pre_passes = $pre:expr; pass = $pass:expr; samples = $s:expr; time = $t:expr) => {
            ::paste::paste! {
                pub fn [<bench_optimize_ $p>](c: &mut Criterion) {
                    let mut group_ls = c.benchmark_group(stringify!([<ls_optimize_ $p>]));
                    group_ls
                        .sample_size($s)
                        .warm_up_time(time::Duration::new(($t as u64).checked_div(2).unwrap(), 0))
                        .measurement_time(time::Duration::new($t, 0));
                    helper_bench_optimization($pre, $pass, group_ls, false);

                    let mut group_netfs = c.benchmark_group(stringify!([<netfs_optimize_ $p>]));
                    group_netfs
                        .sample_size($s)
                        .warm_up_time(time::Duration::new(($t as u64).checked_div(2).unwrap(), 0))
                        .measurement_time(time::Duration::new($t, 0));
                    helper_bench_optimization($pre, $pass, group_netfs, true);
                }
            }
        };
    }

    bench_pass!(
        name = intraprocedural_dead_block_elim;
        pre_passes = |_: &mut Project| {};
        pass = |project: &mut Project| {
            run_ir_pass![
                project.program.term,
                (),
                IntraproceduralDeadBlockElimPass,
                vec![],
                &get_debug_settings(),
            ];
        };
        samples = 10;
        time = 60
    );
    bench_pass!(
        name = input_expression_propagation;
        pre_passes = |project: &mut Project| {
            run_ir_pass![
                project.program.term,
                (),
                IntraproceduralDeadBlockElimPass,
                vec![],
                &get_debug_settings(),
            ];
        };
        pass = |project: &mut Project| {
            run_ir_pass![
                project.program.term,
                (),
                InputExpressionPropagationPass,
                vec![],
                &get_debug_settings(),
            ];
        }
    );
    bench_pass!(
        name = trivial_expression_substitution;
        pre_passes = |project: &mut Project| {
            run_ir_pass!{
                project.program.term,
                vec![],
                &get_debug_settings(),
                ((), IntraproceduralDeadBlockElimPass),
                ((), InputExpressionPropagationPass),
            };
        };
        pass = |project: &mut Project| {
            run_ir_pass![
                project.program.term,
                (),
                TrivialExpressionSubstitutionPass,
                vec![],
                &get_debug_settings(),
            ];
        };
        samples = 10;
        time = 60
    );
    bench_pass!(
        name = dead_variable_elim;
        pre_passes = |project: &mut Project| {
            run_ir_pass!{
                project.program.term,
                vec![],
                &get_debug_settings(),
                ((), IntraproceduralDeadBlockElimPass),
                ((), InputExpressionPropagationPass),
                ((), TrivialExpressionSubstitutionPass),
            };
        };
        pass = |project: &mut Project| {
            run_ir_pass![
                project.program.term,
                project.register_set,
                DeadVariableElimPass,
                vec![],
                &get_debug_settings(),
            ];
        }
    );
    bench_pass!(
        name = control_flow_propagation;
        pre_passes = |project: &mut Project| {
            run_ir_pass!{
                project.program.term,
                vec![],
                &get_debug_settings(),
                ((), IntraproceduralDeadBlockElimPass),
                ((), InputExpressionPropagationPass),
                ((), TrivialExpressionSubstitutionPass),
                (project.register_set, DeadVariableElimPass),
            };
        };
        pass = |project: &mut Project| {
            run_ir_pass![
                project.program.term,
                (),
                ControlFlowPropagationPass,
                vec![],
                &get_debug_settings(),
            ];
        }
    );
    bench_pass!(
        name = stack_pointer_alignment_substitution;
        pre_passes = |project: &mut Project| {
            run_ir_pass!{
                project.program.term,
                vec![],
                &get_debug_settings(),
                ((), IntraproceduralDeadBlockElimPass),
                ((), InputExpressionPropagationPass),
                ((), TrivialExpressionSubstitutionPass),
                (project.register_set, DeadVariableElimPass),
                ((), ControlFlowPropagationPass),
            };
        };
        pass = |project: &mut Project| {
            run_ir_pass![
                project.program.term,
                project,
                StackPointerAlignmentSubstitutionPass,
                vec![],
                &get_debug_settings(),
            ];
        }
    );
}

mod cfg {
    //! Benchmarks for CFG construction.

    use super::helpers::*;
    use super::inputs::*;
    use super::*;

    pub fn bench_cfg_construction(c: &mut Criterion) {
        let bench_with_input_loop =
            |pcode_projects: &[&str], binaries: &[&str], mut group: BenchmarkGroup<WallTime>| {
                for (pcode_project_json, binary) in iter::zip(pcode_projects, binaries) {
                    let project = get_project(pcode_project_json, binary);

                    let program_unoptimized = project.program.clone();

                    let optimized_project = into_optimized_project(project);
                    let program_optimized = optimized_project.program;

                    group.bench_with_input(
                        BenchmarkId::new("unoptimized", pcode_project_json),
                        &program_unoptimized,
                        |b, program_unoptimized| {
                            b.iter_with_large_drop(|| graph::get_program_cfg(program_unoptimized));
                        },
                    );
                    group.bench_with_input(
                        BenchmarkId::new("optimized", pcode_project_json),
                        &program_optimized,
                        |b, program_optimized| {
                            b.iter_with_large_drop(|| graph::get_program_cfg(program_optimized));
                        },
                    );
                }

                group.finish();
            };

        let group_ls = c.benchmark_group("ls_cfg_construction");
        bench_with_input_loop(&LS_PCODE_PROJECTS, &LS_BINARIES, group_ls);

        let group_netfs = c.benchmark_group("netfs_cfg_construction");
        bench_with_input_loop(&NETFS_PCODE_PROJECTS, &NETFS_BINARIES, group_netfs);
    }
}

mod cg {
    //! Benchmarks for CG construction.

    use super::helpers::*;
    use super::inputs::*;
    use super::*;

    pub fn bench_cg_construction(c: &mut Criterion) {
        let bench_with_input_loop =
            |pcode_projects: &[&str], binaries: &[&str], mut group: BenchmarkGroup<WallTime>| {
                for (pcode_project_json, binary) in iter::zip(pcode_projects, binaries) {
                    let project = get_project(pcode_project_json, binary);

                    let program_unoptimized = project.program.clone();

                    let optimized_project = into_optimized_project(project);
                    let program_optimized = optimized_project.program;

                    group.bench_with_input(
                        BenchmarkId::new("unoptimized", pcode_project_json),
                        &program_unoptimized,
                        |b, program_unoptimized| {
                            b.iter_with_large_drop(|| {
                                graph::call::CallGraph::new_with_full_cfgs(program_unoptimized)
                            });
                        },
                    );
                    group.bench_with_input(
                        BenchmarkId::new("optimized", pcode_project_json),
                        &program_optimized,
                        |b, program_optimized| {
                            b.iter_with_large_drop(|| {
                                graph::call::CallGraph::new_with_full_cfgs(program_optimized)
                            });
                        },
                    );
                }

                group.finish();
            };

        let group_ls = c.benchmark_group("ls_cg_construction");
        bench_with_input_loop(&LS_PCODE_PROJECTS, &LS_BINARIES, group_ls);

        let group_netfs = c.benchmark_group("netfs_cg_construction");
        bench_with_input_loop(&NETFS_PCODE_PROJECTS, &NETFS_BINARIES, group_netfs);
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .warm_up_time(time::Duration::new(5, 0))
        .measurement_time(time::Duration::new(10, 0));
    targets = cfg::bench_cfg_construction,
        cg::bench_cg_construction,
        optimization::bench_optimize_intraprocedural_dead_block_elim,
        optimization::bench_optimize_input_expression_propagation,
        optimization::bench_optimize_trivial_expression_substitution,
        optimization::bench_optimize_dead_variable_elim,
        optimization::bench_optimize_control_flow_propagation,
        optimization::bench_optimize_stack_pointer_alignment_substitution,
        core_analyses::bench_function_signatures,
        core_analyses::bench_pi,
        core_analyses::bench_string_abstractions,
        checkers::bench_cwe_119,
        checkers::bench_cwe_134,
        checkers::bench_cwe_190,
        checkers::bench_cwe_215,
        checkers::bench_cwe_243,
        checkers::bench_cwe_252,
        checkers::bench_cwe_332,
        checkers::bench_cwe_337,
        checkers::bench_cwe_367,
        checkers::bench_cwe_416,
        checkers::bench_cwe_426,
        checkers::bench_cwe_467,
        checkers::bench_cwe_476,
        checkers::bench_cwe_560,
        checkers::bench_cwe_676,
        checkers::bench_cwe_782,
        checkers::bench_cwe_789,
);
criterion_main!(benches);
