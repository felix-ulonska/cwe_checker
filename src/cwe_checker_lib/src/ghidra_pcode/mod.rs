//! Translation from Pcode to the internal intermediate representation.

use crate::intermediate_representation::{
    Program as IrProgram, Project as IrProject, RuntimeMemoryImage as IrRuntimeMemoryImage,
    Term as IrTerm, Tid,
};
use crate::utils::debug;
use crate::utils::log::{LogMessage, WithLogs};

use std::collections::HashMap;
use std::fmt::{self, Display};

use serde::{Deserialize, Serialize};

mod calling_convention;
use calling_convention::*;
mod datatype_properties;
use datatype_properties::*;
mod pcode_opcode;
use pcode_opcode::*;
mod pcode_operation;
use pcode_operation::*;
mod varnode;
use varnode::*;
mod instruction;
use instruction::*;
mod block;
use block::*;
mod function;
use function::*;
mod program;
use program::*;
mod term;
use term::*;
mod register_properties;
use register_properties::*;
mod memory_block;
use memory_block::*;
pub mod ir_passes;
use ir_passes::*;

/// Rust representation of the Ghidra plugin output.
///
/// The JSON output of the plugin is deserialized into an instance of this type.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct PcodeProject {
    /// The program code.
    program: Program,
    /// Information about all CPU-architecture-specific registers.
    register_properties: Vec<RegisterProperties>,
    /// The CPU-architecture.
    cpu_arch: String,
    /// Imported functions.
    external_functions: HashMap<String, ExternFunction>,
    /// Exported functions.
    entry_points: Vec<String>,
    /// The stack pointer register of the CPU-architecture.
    stack_pointer_register: Varnode,
    /// Information about known calling conventions for the given CPU
    /// architecture.
    calling_conventions: HashMap<String, CallingConvention>,
    /// Contains the properties of C data types, e.g., their size.
    datatype_properties: DatatypeProperties,
    /// Program image base address in memory.
    image_base: String,
    /// Memory Blocks as parsed by Ghidra
    mem_blocks: Vec<MemoryBlock>,
}

impl Display for PcodeProject {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.program)?;
        for blk in &self.mem_blocks {
            writeln!(f, "{}", blk)?;
        }
        Ok(())
    }
}

impl PcodeProject {
    /// Converts this `PcodeProject` to the internal IR.
    ///
    /// `binary_base_address`: The base address of the memory image
    /// of the binary according to the program headers.
    pub fn into_ir_project(
        self,
        binary_base_address: u64,
        debug_settings: &debug::Settings,
    ) -> WithLogs<IrProject> {
        let mut logs = Vec::new();

        let register_map = RegisterMap::new(&self.register_properties);
        let ir_function_terms_map = self.program.to_ir_function_terms_map();

        let address_base_offset =
            match u64::from_str_radix(self.image_base.trim_start_matches("0x"), 16)
                .unwrap()
                .checked_sub(binary_base_address)
            {
                Some(a) => a,
                None => {
                    logs.push(LogMessage::new_info(format!(
                "Base address reported by Ghidra is smaller than actual base address: {} vs 0x{:x}",
                self.image_base, binary_base_address)));

                    0
                }
            };

        let mut ir_program = IrProgram {
            subs: ir_function_terms_map,
            extern_symbols: self
                .external_functions
                .values()
                .map(|ext_fn| {
                    let ext_sym = ext_fn.to_ir_extern_symbol(&self);

                    (ext_sym.tid.clone(), ext_sym)
                })
                .collect(),
            entry_points: self.entry_points.iter().map(Tid::new_function).collect(),
            address_base_offset,
        };
        debug_settings.print(&ir_program, debug::Stage::Ir(debug::IrForm::Early));

        run_ir_pass![
            ir_program,
            (),
            SingleTargetIndirectCallsPass,
            logs,
            debug_settings
        ];
        run_ir_pass![ir_program, (), ReorderFnBlocksPass, logs, debug_settings];
        run_ir_pass!(ir_program, ReplaceCallsToExtFnsPass, logs, debug_settings);
        run_ir_pass![
            ir_program,
            register_map,
            SubregisterSubstitutionPass,
            logs,
            debug_settings
        ];
        run_ir_pass!(ir_program, InliningPass, logs, debug_settings);
        run_ir_pass!(ir_program, NoreturnExtFunctionsPass, logs, debug_settings);
        run_ir_pass!(ir_program, RemoveEmptyFunctionsPass, logs, debug_settings);
        run_ir_pass!(ir_program, PatchCfPass, logs, debug_settings);
        run_ir_pass![ir_program, (), EntryPointsPass, logs, debug_settings];

        debug_assert_postconditions![ir_program, (), SingleTargetIndirectCallsPass];
        debug_assert_postconditions![ir_program, (), ReorderFnBlocksPass];
        debug_assert_postconditions!(ir_program, ReplaceCallsToExtFnsPass);
        debug_assert_postconditions![ir_program, register_map, SubregisterSubstitutionPass];
        debug_assert_postconditions!(ir_program, InliningPass);
        debug_assert_postconditions!(ir_program, NoreturnExtFunctionsPass);
        debug_assert_postconditions!(ir_program, RemoveEmptyFunctionsPass);
        debug_assert_postconditions!(ir_program, PatchCfPass);
        debug_assert_postconditions![ir_program, (), EntryPointsPass];

        ir_program.debug_assert_invariants();

        // TODO: Normalization-Pass that replaces pseudo-call-target-TIDs with
        // the correct target-TID of the corresponding function. ??????

        let ir_project = IrProject {
            program: IrTerm::new(Tid::new_program(&self.image_base), ir_program),
            cpu_architecture: self.cpu_arch,
            stack_pointer_register: self.stack_pointer_register.to_ir_var(),
            calling_conventions: self
                .calling_conventions
                .into_iter()
                .map(|(cconv_name, cconv)| {
                    (
                        cconv_name,
                        cconv
                            .to_ir_calling_convention(&register_map)
                            .move_logs_to(&mut logs)
                            .into_object(),
                    )
                })
                .collect(),
            register_set: register_map.get_base_reg_ir_vars(),
            datatype_properties: self.datatype_properties.into(),
            runtime_memory_image: IrRuntimeMemoryImage::empty(true),
        };

        WithLogs::new(ir_project, logs)
    }
}
