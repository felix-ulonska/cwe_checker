//! Transforming passes that bring the IR to normal form.

use crate::utils::debug;
use crate::utils::log::LogMessage;

mod single_target_indirect_calls;
pub use single_target_indirect_calls::*;

mod entry_points;
pub use entry_points::*;

mod remove_empty_functions;
pub use remove_empty_functions::*;

mod replace_call_to_ext_fn;
pub use replace_call_to_ext_fn::*;

mod inlining;
pub use inlining::*;

mod jump_targets;
pub use jump_targets::*;

mod subregister_substitution;
pub use subregister_substitution::*;

mod fn_start_blocks;
pub use fn_start_blocks::*;

mod nonret_ext_functions;
pub use nonret_ext_functions::*;

pub mod prelude {
    //! Prelude imports for IR passes.
    pub use super::IrPass;
    pub use crate::intermediate_representation::Program;
    pub use crate::utils::debug;
    pub use crate::utils::log::LogMessage;
}

/// # Guarantees
///
/// A list of predicates about the program that are preserved if they are true
/// before the pass.
///
/// # Postconditions
///
/// A list of predicates about the program that are always true after the pass.
/// Every following transformation is expected to preserve these predicates,
/// i.e., they are assumed to remain true.
/// [Parts of the Postcondition that are not checked by
/// [`IrPass::assert_postconditions`]]
///
/// # Run After
///
/// There is a partial ordering between IR passes. `pass0 < pass1` means that
/// `pass0` always has to run before `pass1`. This section lists all passes that
/// are strictly less than the current pass.
pub trait IrPass {
    /// Name of this pass.
    // Use std::any::type_name once it is stable as const fn.
    const NAME: &'static str;
    /// Form of the IR __after__ this pass.
    const DBG_IR_FORM: debug::IrForm;

    /// Type of the input that the pass runs on.
    type Input;
    /// Type of the input that the pass constructor needs.
    type ConstructionInput;

    /// Constructs a new instance of this pass.
    fn new(construction_input: &Self::ConstructionInput) -> Self;

    /// Runs the pass on the given program.
    fn run(&mut self, program: &mut Self::Input) -> Vec<LogMessage>;

    /// Asserts that the program satisfies all Postconditions of this pass.
    fn assert_postconditions(construction_input: &Self::ConstructionInput, program: &Self::Input);
}

/// Runs an IR pass on the given program.
#[macro_export]
macro_rules! run_ir_pass {
    // Run a sequence of IR passes.
    {
        $program:expr,
        $logs:expr,
        $dbg_settings:expr,
        $(($construction_input:expr, $pass:ty)),+$(,)?
    } => {
        $(
            run_ir_pass![
                $program,
                $construction_input,
                $pass,
                $logs,
                $dbg_settings,
            ];
        )+
    };
    // Run a single IR pass where the construction input is the program.
    ($program:expr, $pass:ty, $logs:expr, $dbg_settings:expr$(,)?) => {
        run_ir_pass![$program, $program, $pass, $logs, $dbg_settings]
    };
    [$program:expr, $construction_input:expr, $pass:ty, $logs:expr, $dbg_settings:expr$(,)?] => {
        let mut pass = <$pass>::new(&$construction_input);
        let mut logs = pass.run(&mut $program);

        if $dbg_settings.verbose() {
            println!("[IR-PASSES] Finished pass: {}", <$pass>::NAME);
            for msg in logs.iter() {
                println!("  {}", msg);
            }
        }
        if !$dbg_settings.quiet() {
            $logs.append(&mut logs);
        }

        $dbg_settings.print(&$program, $crate::utils::debug::Stage::Ir(<$pass>::DBG_IR_FORM));
    };
}
pub use run_ir_pass;

/// Asserts that the postconditions of an IR pass are satisfied by the given
/// program.
///
/// Only active if debug assertions are enabled.
#[macro_export]
macro_rules! debug_assert_postconditions {
    ($program:expr, $pass:ty$(,)?) => {
        debug_assert_postconditions![$program, $program, $pass];
    };
    [$program:expr, $construction_input:expr, $pass:ty$(,)?] => {
        if cfg!(debug_assertions) {
            <$pass>::assert_postconditions(&$construction_input, &$program);
        }
    }
}
pub use debug_assert_postconditions;
