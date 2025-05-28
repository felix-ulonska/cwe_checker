use ascent::hashbrown::HashMap;

use crate::{
    analysis::indirect_call_recovery::{
        function_taken::{get_at_functions, get_at_functions_by_key},
        memory_block_gen::global_block::Interval,
    },
    intermediate_representation::{BinOpType, Project},
    prelude::{Bitvector, BitvectorExtended},
};

use super::{context::MemorySegmentWithInterval, utils::build_mem_segments_with_interval};

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
        if segment.segment.read_flag && segment.interval.contains(&Bitvector::from_u64(constant)) {
            return true;
        }
    }
    false
}

pub struct GlobalMemContent {
    content_global_mem: HashMap<Interval, Vec<u64>>,
}

impl GlobalMemContent {
    pub fn new(project: &Project, intervals: &Vec<Interval>) -> Self {
        let at_functions = get_at_functions_by_key(project);
        let memory_segements = build_mem_segments_with_interval(&project.runtime_memory_image);
        let ptr_byte_size = project.get_pointer_bytesize().as_bit_length() / 8;
        let mut global_content = HashMap::new();

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
                    curr_addr += ptr_byte_size as u64;
                    continue;
                }

                // Check if global mem section
                if let Some(curr_interval) = intervals
                    .iter()
                    .find(|interval| interval.contains_i64(curr_addr as i64))
                {
                    global_content
                        .entry(curr_interval.clone())
                        .or_insert_with(Vec::new)
                        .push(ptr_as_num);
                };
                curr_addr += ptr_byte_size as u64;
            }
        }

        Self {
            content_global_mem: global_content,
        }
    }

    pub fn iter_content(&self) -> ascent::hashbrown::hash_map::Iter<'_, Interval, Vec<u64>> {
        self.content_global_mem.iter()
    }
}

fn read(
    address: u64,
    size: u64,
    memory_segments: &Vec<MemorySegmentWithInterval>,
    is_little_endian: bool,
) -> Option<u64> {
    for segment in memory_segments.iter() {
        let segment = segment.segment;
        if address >= segment.base_address
            && u64::from(size) <= segment.base_address + segment.bytes.len() as u64
            && address <= segment.base_address + segment.bytes.len() as u64 - u64::from(size)
        {
            let index = (address - segment.base_address) as usize;
            let mut bytes = segment.bytes[index..index + u64::from(size) as usize].to_vec();
            if is_little_endian {
                bytes = bytes.into_iter().rev().collect();
            }
            let mut bytes = bytes.into_iter();
            let mut bitvector = Bitvector::from_u8(bytes.next().unwrap());
            for byte in bytes {
                let new_byte = Bitvector::from_u8(byte);
                bitvector = bitvector.bin_op(BinOpType::Piece, &new_byte).unwrap();
            }
            return bitvector.try_to_u64().ok();
        }
    }
    // No segment fully contains the read.
    None
}
