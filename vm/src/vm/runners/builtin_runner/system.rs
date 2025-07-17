use num_integer::div_ceil;

use crate::{
    types::{
        instance_definitions::system_instance_def::CELLS_PER_SYSTEM, relocatable::MaybeRelocatable,
    },
    vm::{errors::memory_errors::MemoryError, vm_memory::memory_segments::MemorySegmentManager},
};

#[derive(Debug, Clone)]
pub struct SystemBuiltinRunner {
    pub base: usize,
    pub(crate) stop_ptr: Option<usize>,
    pub(crate) included: bool,
}

impl SystemBuiltinRunner {
    pub fn new(included: bool) -> Self {
        SystemBuiltinRunner {
            base: 0,
            stop_ptr: None,
            included,
        }
    }
}

impl SystemBuiltinRunner {
    pub fn initialize_segments(&mut self, segments: &mut MemorySegmentManager) {
        self.base = segments.add().segment_index as usize // segments.add() always returns a positive index
    }

    pub fn initial_stack(&self) -> Vec<MaybeRelocatable> {
        if self.included {
            vec![MaybeRelocatable::from((self.base as isize, 0))]
        } else {
            vec![]
        }
    }

    pub fn base(&self) -> usize {
        self.base
    }

    pub fn ratio(&self) -> Option<u32> {
        None
    }

    pub fn get_used_cells(&self, segments: &MemorySegmentManager) -> Result<usize, MemoryError> {
        segments
            .get_segment_used_size(self.base())
            .ok_or(MemoryError::MissingSegmentUsedSizes)
    }

    pub fn get_used_instances(
        &self,
        segments: &MemorySegmentManager,
    ) -> Result<usize, MemoryError> {
        let used_cells = self.get_used_cells(segments)?;
        Ok(div_ceil(used_cells, CELLS_PER_SYSTEM as usize))
    }
}
