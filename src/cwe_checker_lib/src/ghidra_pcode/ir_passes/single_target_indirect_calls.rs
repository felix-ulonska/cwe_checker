use super::prelude::*;
use crate::intermediate_representation::{Jmp, Term};

/// Replaces indirect calls with a single target with a direct call to this
/// target.
///
/// # Guarantees
///
/// # Postconditions
///
/// - A block has `Some` list of indirect control flow targets IFF it ends in
///   an indirect jump or call. The type of the indirect control flow targets
///   fits to the type of the indirect control flow transfer.
///
/// # Run After
pub struct SingleTargetIndirectCallsPass;

impl IrPass for SingleTargetIndirectCallsPass {
    const NAME: &'static str = "SingleTargetIndirectCallsPass";
    const DBG_IR_FORM: debug::IrForm = debug::IrForm::SingleTargetIndirectCallsReplaced;

    type Input = Program;
    type ConstructionInput = ();

    fn new(_construction_input: &Self::ConstructionInput) -> Self {
        Self
    }

    fn run(&mut self, program: &mut Self::Input) -> Vec<LogMessage> {
        let mut logs = Vec::new();

        for b in program.blocks_mut() {
            // Filter blocks that end in an indirect call with a single target.
            let Some(Term { term: j, tid }) = b.jmps().last() else {
                continue;
            };
            let Jmp::CallInd {
                return_: return_target,
                ..
            } = j
            else {
                continue;
            };
            let mut indirect_call_targets = b.ind_call_targets().unwrap();
            let Some(first_target) = indirect_call_targets.next().cloned() else {
                continue;
            };
            if indirect_call_targets.next().is_some() {
                continue;
            }
            std::mem::drop(indirect_call_targets);

            logs.push(LogMessage::new_info(format!(
                "{}: Replaced single-target indirect call at {} with direct call to {}.",
                Self::NAME,
                tid,
                first_target
            )));

            // Change to a direct call.
            b.jmps_mut().last().unwrap().term = Jmp::Call {
                target: first_target,
                return_: return_target.clone(),
            };

            // Restore invariant that only blocks with indirect calls or jumps
            // have `Some` indirect control flow targets.
            b.clear_ind_control_flow_targets();
        }

        logs
    }

    fn assert_postconditions(_construction_input: &Self::ConstructionInput, program: &Self::Input) {
        for b in program.blocks() {
            match b.jmps().last() {
                None => assert!(b.ind_control_flow_targets().is_none()),
                Some(j) => match &j.term {
                    Jmp::BranchInd(_) => {
                        assert!(b.ind_control_flow_targets().is_some());
                        assert!(b.ind_jump_targets().is_some());
                    }
                    Jmp::CallInd { .. } => {
                        assert!(b.ind_control_flow_targets().is_some());
                        assert!(b.ind_call_targets().is_some());
                    }
                    _ => assert!(b.ind_control_flow_targets().is_none()),
                },
            }
        }
    }
}
