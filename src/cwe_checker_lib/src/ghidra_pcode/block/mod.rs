use super::JmpOpcode::*;
use crate::ghidra_pcode::{Instruction, PcodeOpcode, Term};
use crate::intermediate_representation::{Blk as IrBlock, Jmp as IrJmp, Term as IrTerm, Tid};

use std::collections::HashSet;
use std::iter::Peekable;

use serde::{Deserialize, Serialize};

/// Iterator-like struct for iterating over the P-Code operations contained in a
/// slice of [`Instruction`] objects.
struct OpIterator<'a> {
    /// The iterator over the assembly instructions.
    instr_iter: Peekable<std::slice::Iter<'a, Instruction>>,
    /// The iterator over the P-Code instructions contained in the current
    /// assembly instruction.
    term_iter: Option<Peekable<std::slice::Iter<'a, Term>>>,
    /// The current assembly instruction.
    current_instr: Option<&'a Instruction>,
    /// The list of known jump targets.
    jump_targets: &'a HashSet<Tid>,
}

impl<'a> OpIterator<'a> {
    /// Create a new iterator out of a slice and the list of known jump targets.
    pub fn new(instructions: &'a [Instruction], jump_targets: &'a HashSet<Tid>) -> Self {
        Self {
            instr_iter: instructions.iter().peekable(),
            term_iter: None,
            current_instr: None,
            jump_targets,
        }
    }

    /// Get the next instruction.
    ///
    /// Advances the instruction iterator and resets the P-code operation
    /// iterator accordingly.
    fn next_instr(&mut self) -> Option<&'a Instruction> {
        if let Some(instr) = self.instr_iter.next() {
            self.term_iter = Some(instr.terms().iter().peekable());
            self.current_instr = Some(instr);
            Some(instr)
        } else {
            self.term_iter = None;
            self.current_instr = None;
            None
        }
    }

    /// Get the next Pcode term.
    ///
    /// Advances the Pcode term iterator, may also advance the instruction
    /// iterator.
    fn next_term(&mut self) -> Option<&'a Term> {
        match self.next_instr_term() {
            Some(term) => Some(term),
            None => match self.next_instr() {
                Some(_) => self.next_term(),
                None => None,
            },
        }
    }

    /// Get the next Pcode term in the current assembly instruction.
    ///
    /// Advances the Pcode term iterator.
    fn next_instr_term(&mut self) -> Option<&'a Term> {
        self.term_iter
            .as_mut()
            .map(|term_iter| term_iter.next())
            .unwrap_or_default()
    }

    /// Peek the next assembly instruction without advancing the iterator.
    fn peek_next_instr(&mut self) -> Option<&'a Instruction> {
        self.instr_iter.peek().copied()
    }

    /// Peek the next Pcode term in the current assembly instruction without
    /// advancing the iterator.
    fn peek_next_instr_term(&mut self) -> Option<&'a Term> {
        if let Some(term) = self.term_iter.as_mut().map(|term_iter| term_iter.peek()) {
            term.copied()
        } else {
            None
        }
    }

    /// Peek the next Pcode term without advancing the iterator.
    fn peek_next_term(&mut self) -> Option<&'a Term> {
        match self.peek_next_instr_term() {
            Some(term) => Some(term),
            None => self
                .peek_next_instr()
                .map(|instr| instr.terms().first())
                .unwrap_or_default(),
        }
    }

    /// Returns the block Tid of the next instruction (either a P-Code term or
    /// an assembly instruction).
    fn peek_next_blk_tid(&mut self) -> Option<Tid> {
        if let Some(term) = self.peek_next_instr_term() {
            Some(Tid::new_block(term.address(), term.index()))
        } else {
            self.peek_next_instr()
                .map(|instr| Tid::new_block(instr.address(), 0))
        }
    }

    /// If the next instruction, which is either a P-Code term or an assembly
    /// instruction, is a jump target, then return the corresponding block TID.
    fn peek_for_jmp_target(&mut self) -> Option<Tid> {
        let next_blk_tid = self.peek_next_blk_tid();
        if next_blk_tid
            .as_ref()
            .is_some_and(|tid| self.jump_targets.contains(tid))
        {
            next_blk_tid
        } else {
            None
        }
    }

    /// Return `true` if the next P-Code term is a jump.
    fn peek_for_jmp_term(&mut self) -> bool {
        self.peek_next_term()
            .is_some_and(|term| matches!(term.opcode(), PcodeOpcode::Jump(_)))
    }

    /// Advance the iterator until one of the following occurs:
    /// - The peeked next instruction would be a jump target not equal to the
    ///   given block Tid. Return None.
    ///   (The comparison with the given block TID ensures that Defs are added
    ///   to blocks starting with a jump target.)
    /// - The peeked next instruction is a jump. Return None.
    /// - A P-Code operation corresponding to a `Def` is reached.
    ///   Yield the term.
    pub fn next_def_term(&mut self, block_tid: &Tid) -> Option<&'a Term> {
        loop {
            if self
                .peek_for_jmp_target()
                .is_some_and(|jmp_target| jmp_target != *block_tid)
                || self.peek_for_jmp_term()
            {
                return None;
            } else if let Some(term) = self.next_instr_term() {
                return Some(term);
            } else if self.peek_next_instr().is_none() {
                // We reached the end of the iterator.
                return None;
            } else {
                // Forward to next instruction and repeat the loop.
                self.next_instr();
            }
        }
    }

    /// If the next Pcode term is a jump, yield the term.
    ///
    /// Advances the term iterator, may also advance the instruction iterator.
    pub fn next_if_jmp_term(&mut self) -> Option<&'a Term> {
        if !self.peek_for_jmp_term() {
            None
        } else {
            self.next_term()
        }
    }

    /// Uses the iterator to translate current operation and following into Defs and adds them to the block.
    /// Returns if current operation is a jump target, or a jump operation.
    fn drain_defs_into_block<'b>(
        &mut self,
        block: &'b mut IrTerm<IrBlock>,
    ) -> &'b mut IrTerm<IrBlock> {
        while let Some(term) = self.next_def_term(&block.tid) {
            block.term.defs.append(&mut term.to_ir_def_terms());
        }

        block
    }

    /// Add jumps to the block depending on the situation:
    /// - If the next instruction in the iterator is a jump target, then add a
    ///   fallthrough jump to that instruction to the block.
    /// - Else if the next instruction is a jump, create the corresponding
    ///   IR-jumps and add them to the block.
    /// - Else if the current (and only) instruction in the block is in a MIPS
    ///   Jump Delay Slot indicate that the block we are building should be
    ///   dropped.
    /// - Else try to add a fallthrough jump to the next block on a best-effort
    ///   basis.
    fn drain_jump_into_block<'b>(
        &mut self,
        block: &'b mut IrTerm<IrBlock>,
    ) -> Result<&'b mut IrTerm<IrBlock>, ()> {
        if self
            .peek_for_jmp_target()
            .is_some_and(|target_tid| target_tid != block.tid)
        {
            // The target is not the very first instruction of the block
            let fall_through_jmp_tid = create_fall_through_jmp_tid_for_blk(block);
            let fall_through_jmp = IrTerm::new(
                fall_through_jmp_tid,
                IrJmp::Branch(self.peek_for_jmp_target().unwrap()),
            );
            block.term.jmps.push(fall_through_jmp);

            Ok(block)
        } else if let Some(jmp_term) = self.next_if_jmp_term() {
            add_jmp_to_blk(
                &mut block.term,
                self.current_instr.unwrap(),
                jmp_term,
                self.peek_next_instr(),
            );

            Ok(block)
        } else if let Some(instr) = self.current_instr {
            if instr.is_mips_jump_delay_slot() {
                return Err(());
            }

            let fall_through_jmp_tid = create_fall_through_jmp_tid_for_blk(block);
            let Some(fallthrough_address) = instr.fall_through() else {
                // Weird, but it seems to happen very rarely so we ignore it.
                // Until now only for hppa arch.
                return Err(());
            };
            let fallthrough_block_tid = Tid::new_block(fallthrough_address, 0);
            let fall_through_jmp =
                IrTerm::new(fall_through_jmp_tid, IrJmp::Branch(fallthrough_block_tid));
            block.term.jmps.push(fall_through_jmp);

            Ok(block)
        } else {
            panic!("Unable to close block with a jump.")
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Block {
    address: String,
    instructions: Vec<Instruction>,
}

impl Block {
    /// Returns a reference to the assembly instructions in this block.
    pub fn instructions(&self) -> &Vec<Instruction> {
        &self.instructions
    }

    /// Returns a one-line signature of this block.
    pub fn summary_string(&self) -> String {
        format!("BLOCK @ {}", self.address)
    }

    /// Collects all jumps targets of instructions within the block.
    ///
    /// A block [`Tid`] is created for every jump target using the id scheme
    ///     `blk_<addr>` \[`_<index>`\],
    /// with the optional `_<index>` denoting the pcode operation index for
    /// intra instruction jumps. `<addr>` denotes the address of the target
    /// block that might be created additionally to Ghidras basic blocks.
    ///
    /// If a pcode relative jump implies a jump to the next instruction, the
    /// instruction's address is derived in the following order:
    /// 1. use instructions's falltrough address,
    /// 2. use the block's consecutive instruction, // Not implemented.
    /// 3. compute the address.                     // Not implemented.
    pub fn collect_jmp_targets(&self) -> HashSet<Tid> {
        let mut jump_targets = HashSet::new();
        let mut instructions = self.instructions.iter().peekable();

        while let Some(instr) = instructions.next() {
            jump_targets
                .extend(instr.collect_jmp_and_fall_through_targets(instructions.peek().copied()))
        }

        jump_targets
    }

    /// Translates a Basic block by Ghidra into one or many IR basic blocks.
    pub fn to_ir_blocks(&self, jump_targets: &HashSet<Tid>) -> Vec<IrTerm<IrBlock>> {
        let mut finalized_blocks = vec![];

        // The iterator provides the currently pcode operation together with its instruction.
        let mut iterator = OpIterator::new(&self.instructions[..], jump_targets);

        // While a current operation is present, translate it and add it to a block...
        while let Some(tid) = iterator.peek_next_blk_tid() {
            let mut block = IrTerm {
                tid: tid.clone(),
                term: IrBlock::new(),
            };

            iterator.drain_defs_into_block(&mut block);

            if iterator.drain_jump_into_block(&mut block).is_ok() {
                finalized_blocks.push(block);
            }
        }

        finalized_blocks
    }
}

/// Returns the TID of an implicit jump instruction that gets added to a block
/// when it does not end in a jump in Ghidra but falls through to the next
/// instruction.
fn create_fall_through_jmp_tid_for_blk(block: &IrTerm<IrBlock>) -> Tid {
    if let Some(last_def) = block.term.defs.last() {
        last_def.tid.clone().with_id_suffix("_fall_through_jump")
    } else {
        block
            .tid
            .clone()
            .into_instr()
            .with_id_suffix("_fall_through_jump")
    }
}

/// Add the given jump operation to the block and, if necessary, a second
/// fallthrough jump instruction.
fn add_jmp_to_blk<'a>(
    ir_blk: &'a mut IrBlock,
    instr: &Instruction,
    jmp_term: &Term,
    _next_instr: Option<&Instruction>,
) -> &'a mut IrBlock {
    let add_jmp_to_block_closure = |ir_blk: &mut IrBlock, instr: &Instruction, jmp_term: &Term| {
        match jmp_term.unwrap_jmp_opcode() {
            BRANCH | RETURN | CALL | CALLOTHER => {
                let branch = jmp_term.to_ir_jump_term(instr);
                ir_blk.jmps.push(branch);
            }
            BRANCHIND => {
                let branch = jmp_term.to_ir_jump_term(instr);
                ir_blk.jmps.push(branch);
                if let Some(targets) = instr.potential_targets() {
                    ir_blk.set_ind_jump_targets(
                        targets.iter().map(|target| Tid::new_block(target, 0)),
                    );
                }
            }
            CALLIND => {
                let branch = jmp_term.to_ir_jump_term(instr);
                ir_blk.jmps.push(branch);
                if let Some(targets) = instr.potential_targets() {
                    ir_blk.set_ind_call_targets(targets.iter().map(Tid::new_function));
                }
            }
            // Add conditional branch and then implicit branch
            CBRANCH => {
                let cbranch = jmp_term.to_ir_jump_term(instr);
                let fall_through = jmp_term
                    .get_fall_through_target(instr)
                    .expect("Expected fall through for conditional branch.");
                let fall_through_jump = IrTerm::new(
                    Tid::new_instr_with_suffix(
                        instr.address(),
                        jmp_term.index(),
                        Some("fall_through_jump"),
                    ),
                    IrJmp::Branch(fall_through),
                );
                ir_blk.jmps.push(cbranch);
                ir_blk.jmps.push(fall_through_jump);
            }
        }
    };

    if jmp_term.has_implicit_load_for_jump() {
        let mut term_to_convert = jmp_term.clone();

        ir_blk.defs.push(
            term_to_convert.make_input_explicitly_loaded_and_return_ir_def_load_term_for_jump(),
        );

        add_jmp_to_block_closure(ir_blk, instr, &term_to_convert);
    } else {
        add_jmp_to_block_closure(ir_blk, instr, jmp_term);
    }

    ir_blk
}

// TODO: Fix tests.
//#[cfg(test)]
//pub mod tests;
