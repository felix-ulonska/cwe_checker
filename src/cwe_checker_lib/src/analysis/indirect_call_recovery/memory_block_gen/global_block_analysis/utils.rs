use crate::{abstract_domain::Interval, intermediate_representation::RuntimeMemoryImage};

use super::context::MemorySegmentWithInterval;

pub fn build_mem_segments_with_interval<'a>(
    runtime_memory_image: &'a RuntimeMemoryImage,
) -> Vec<MemorySegmentWithInterval<'a>> {
    let mut memory_segements = vec![];
    for segment in &runtime_memory_image.memory_segments {
        memory_segements.push(MemorySegmentWithInterval {
            interval: Interval::new(
                segment.base_address.into(),
                (segment.base_address + segment.bytes.len() as u64).into(),
                1,
            ),
            segment,
        });
    }

    memory_segements
}
