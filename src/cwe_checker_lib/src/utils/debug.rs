//! Little helpers for developers that try to understand what their code is
//! doing.

#![allow(dead_code)]
#![allow(missing_docs)]

use std::path::PathBuf;

#[derive(PartialEq, Eq, Copy, Clone, Debug, Default)]
/// Stages of the analysis that can be debugged separately.
#[non_exhaustive]
pub enum Stage {
    #[default]
    No,
    All,
    /// Construction of whole-program call graph.
    CallGraph,
    /// Construction of whole-program control flow graph.
    ControlFlowGraph,
    /// Pointer inference.
    Pi,
    /// Generation of intermediate representation.
    Ir(IrForm),
    /// Parsing of Pcode.
    Pcode(PcodeForm),
    /// CWE checkers.
    Cwe,
}

#[derive(PartialEq, Eq, Copy, Clone, Debug)]
/// Substages of the IR generation that can be debugged separately.
#[non_exhaustive]
pub enum IrForm {
    /// The very first IR representation of the program.
    Early,
    /// Indirect calls with a single target have been replaced by direct calls
    /// to this target.
    SingleTargetIndirectCallsReplaced,
    /// After blocks within a function have been normal ordered.
    FnBlksSorted,
    /// After non-returning external functions have been marked.
    NonRetExtFunctionsMarked,
    /// After calls to stubs for external functions have been replaced with
    /// calls to the external function.
    ExtCallsReplaced,
    /// After existing, referenced blocks have blocks have been inlined into
    /// functions.
    Inlined,
    /// After the subregister substitution pass.
    SubregistersSubstituted,
    /// After all control flow transfers have a valid target.
    CfPatched,
    /// After empty functions have been removed.
    EmptyFnRemoved,
    /// After nonexisting entry points have been removed.
    EntryPointsExist,
    /// The unoptimized IR.
    Raw,
    /// After unreachable basic blocks have been removed from functions.
    IntraproceduralDeadBlocksElimed,
    /// After trivial expressions have been replaced with their results.
    TrivialExpressionsSubstituted,
    /// After input expressions have been propagated along variable assignments.
    InputExpressionsPropagated,
    /// After assignments to dead variables have been removed.
    DeadVariablesElimed,
    /// After control flow across conditionals with the same condition has been
    /// simplified.
    ControlFlowPropagated,
    /// After stack pointer alignment via logical AND has been substituted with
    /// a subtraction operation.
    StackPointerAlignmentSubstituted,
    /// The final IR.
    Optimized,
}

#[derive(PartialEq, Eq, Copy, Clone, Debug)]
/// Substages of the Pcode transformation that can be debugged separately.
#[non_exhaustive]
pub enum PcodeForm {
    /// The JSON string that comes from the Ghidra plugin.
    Raw,
    Parsed,
    Processed,
}

#[derive(PartialEq, Eq, Copy, Clone, Debug, Default)]
/// Controls generation of log messages.
#[non_exhaustive]
pub enum Verbosity {
    Quiet,
    #[default]
    Normal,
    Verbose,
}

#[derive(PartialEq, Eq, Copy, Clone, Debug, Default)]
/// Selects whether the analysis is aborted after reaching the point of
/// interest.
#[non_exhaustive]
pub enum TerminationPolicy {
    KeepRunning,
    #[default]
    EarlyExit,
    Panic,
}

#[derive(PartialEq, Eq, Clone, Default, Debug)]
/// Configuration of the debugging behavior.
pub struct Settings {
    stage: Stage,
    verbose: Verbosity,
    terminate: TerminationPolicy,
    saved_pcode_raw: Option<PathBuf>,
}

#[derive(PartialEq, Eq, Clone, Default, Debug)]
pub struct SettingsBuilder {
    inner: Settings,
}

impl SettingsBuilder {
    pub fn build(self) -> Settings {
        self.inner
    }

    pub fn set_stage(mut self, stage: Stage) -> Self {
        self.inner.stage = stage;

        self
    }

    pub fn set_verbosity(mut self, verbosity: Verbosity) -> Self {
        self.inner.verbose = verbosity;

        self
    }

    pub fn set_termination_policy(mut self, policy: TerminationPolicy) -> Self {
        self.inner.terminate = policy;

        self
    }

    pub fn set_saved_pcode_raw(mut self, saved_pcode_raw: PathBuf) -> Self {
        self.inner.saved_pcode_raw = Some(saved_pcode_raw);

        self
    }
}

impl Settings {
    pub fn get_saved_pcode_raw(&self) -> Option<PathBuf> {
        self.saved_pcode_raw.clone()
    }

    /// Returns true iff the `stage` is being debugged.
    pub fn should_debug(&self, stage: Stage) -> bool {
        debug_assert_ne!(stage, Stage::No);

        stage == self.stage || matches!(stage, Stage::All)
    }

    /// Displays the `obj`ect if the stage is being debugged.
    ///
    /// This is a possible cancellation point depending on the termination
    /// policy.
    pub fn print<T: std::fmt::Display>(&self, obj: &T, stage: Stage) {
        if self.should_debug(stage) {
            println!("{}", obj);
            self.maybe_terminate();
        }
    }

    /// Displays the `obj`ect if the stage is being debugged.
    ///
    /// This is a possible cancellation point depending on the termination
    /// policy.
    pub fn print_compact_json<T: ToJsonCompact>(&self, obj: &T, stage: Stage) {
        if self.should_debug(stage) {
            obj.print_compact_json();
            self.maybe_terminate();
        }
    }

    /// Displays the `obj`ect if the stage is being debugged.
    ///
    /// This is a possible cancellation point depending on the termination
    /// policy.
    pub fn dbg<T: std::fmt::Debug>(&self, obj: &T, stage: Stage) {
        if self.should_debug(stage) {
            println!("{:?}", obj);
            self.maybe_terminate();
        }
    }

    /// Terminates the process according to the termination policy.
    fn maybe_terminate(&self) {
        match self.terminate {
            TerminationPolicy::EarlyExit => std::process::exit(0),
            TerminationPolicy::Panic => panic!(),
            _ => (),
        }
    }

    /// Returns true if the logging level is at least verbose.
    pub fn verbose(&self) -> bool {
        matches!(self.verbose, Verbosity::Verbose)
    }

    /// Returns true if logging is disabled.
    pub fn quiet(&self) -> bool {
        matches!(self.verbose, Verbosity::Quiet)
    }
}

/// Central utility for debug printing in the `cwe_checker`.
///
/// The canonical way to do printf-debugging in `cwe_checker` development is to
/// implement this trait for the type you want to inspect and then print it
/// via `value.print_compact_json()`.
pub trait ToJsonCompact {
    /// Returns a json representation of values of type `self` that is
    /// suitable for debugging purposes.
    ///
    /// The idea is that printing of complex types is facilitated by
    /// implementing `to_json_compact` for all of their constituent parts.
    fn to_json_compact(&self) -> serde_json::Value;

    /// Print values of type `Self` for debugging purposes.
    fn print_compact_json(&self) {
        println!("{:#}", self.to_json_compact())
    }
}
