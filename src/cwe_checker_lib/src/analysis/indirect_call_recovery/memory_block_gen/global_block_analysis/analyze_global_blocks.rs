use crate::{
    analysis::indirect_call_recovery::memory_block_gen::global_block::Interval,
    intermediate_representation::Project, prelude::Bitvector,
};

use super::{
    context::{Data, MemorySegmentWithInterval},
    utils::build_mem_segments_with_interval,
    vsa_result::GlobalBlockAnalysisResult,
};

pub fn bytes_to_u64(bytes: &[u8], is_little_endia: bool) -> u64 {
    let mut buf = [0u8; 8]; // All zeros by default
    let len = bytes.len().min(8);
    buf[..len].copy_from_slice(&bytes[..len]);
    if is_little_endia {
        u64::from_le_bytes(buf)
    } else {
        u64::from_be_bytes(buf)
    }
}

fn is_ptr(constant: u64, memory_segments: &Vec<MemorySegmentWithInterval>) -> bool {
    for segment in memory_segments {
        if segment.interval.contains(&Bitvector::from_u64(constant)) {
            return true;
        }
    }
    false
}

fn analyze_global_blks(
    project: &Project,
    global_block_analysis: GlobalBlockAnalysisResult,
    intervals: &Vec<Interval>,
) {
    let memory_segements = build_mem_segments_with_interval(&project.runtime_memory_image);
    let ptr_byte_size = project.get_pointer_bytesize().as_bit_length() / 8;
    for mem_segment in &project.runtime_memory_image.memory_segments {
        // check aligned
        let start_addr = mem_segment.base_address;
        let mut curr_addr = start_addr;
        for potential_ptr in mem_segment.bytes.chunks_exact(ptr_byte_size) {
            // Check if global ptr
            let ptr_as_num = bytes_to_u64(
                potential_ptr,
                project.runtime_memory_image.is_little_endian_byte_order(),
            );

            if !is_ptr(ptr_as_num, &memory_segements) {
                continue;
            }

            // Check if global mem section
            let Some(curr_interval) = intervals
                .iter()
                .find(|interval| interval.contains_i64(curr_addr as i64))
            else {
                continue;
            };
            curr_addr += ptr_byte_size as u64;
        }
    }
}
