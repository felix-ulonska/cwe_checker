use super::prelude::*;

use crate::intermediate_representation::Tid;

/// Ensures that the first block of a function is its entry point.
///
/// # Postconditions
///
/// 1. Each nonempty function has exactly one block that has the same address as
///    the function.
/// 2. This block is in the first position in the block array.
///
/// # Run After
pub struct ReorderFnBlocksPass;

impl ReorderFnBlocksPass {
    /// Returns true iff `b` is a start block for `f`.
    fn is_fn_start_blk(f: &Tid, b: &Tid) -> bool {
        f.address() == b.address() && (b.is_block_without_suffix() || b.is_artificial_sink_block())
    }
}

impl IrPass for ReorderFnBlocksPass {
    const NAME: &'static str = "ReorderFnBlocksPass";
    const DBG_IR_FORM: debug::IrForm = debug::IrForm::FnBlksSorted;

    type Input = Program;
    type ConstructionInput = ();

    fn new(_construction_input: &Self::ConstructionInput) -> Self {
        Self
    }

    fn run(&mut self, program: &mut Self::Input) -> Vec<LogMessage> {
        let mut logs = Vec::new();

        for f in program.functions_mut().filter(|f| {
            !f.blocks.is_empty() && !Self::is_fn_start_blk(&f.tid, &f.blocks().next().unwrap().tid)
        }) {
            let (idx, _) = f
                .blocks()
                .enumerate()
                .find(|(_, b)| Self::is_fn_start_blk(&f.tid, &b.tid))
                .unwrap();

            logs.push(LogMessage::new_info(format!(
                "{}: Start block of function {} was at idx {}.",
                Self::NAME,
                f.tid,
                idx
            )));

            f.blocks.swap(0, idx);
        }

        logs
    }

    fn assert_postconditions(_construction_input: &Self::ConstructionInput, program: &Self::Input) {
        for f in program.functions().filter(|f| !f.blocks.is_empty()) {
            // 1. Each nonempty function has exactly one block that has the same
            //    address as the function.
            assert_eq!(
                f.blocks()
                    .filter(|b| Self::is_fn_start_blk(&f.tid, &b.tid))
                    .count(),
                1,
                "Function {} has {} entry blocks: {}",
                &f.tid,
                f.blocks()
                    .filter(|b| Self::is_fn_start_blk(&f.tid, &b.tid))
                    .count(),
                f.blocks()
                    .filter(|b| Self::is_fn_start_blk(&f.tid, &b.tid))
                    .fold(String::new(), |mut a, i| {
                        a.push_str(format!("{},", i.tid.to_string()).as_str());
                        a
                    })
            );
            // 2. This block is in the first position in the block array.
            assert!(Self::is_fn_start_blk(&f.tid, &f.blocks().next().unwrap().tid));
        }
    }
}
