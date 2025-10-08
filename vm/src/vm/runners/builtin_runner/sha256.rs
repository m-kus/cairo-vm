use crate::air_private_input::{PrivateInput, PrivateInputSha256State};
use crate::stdlib::{cell::RefCell, collections::HashMap, prelude::*};
use crate::types::builtin_name::BuiltinName;

use crate::types::instance_definitions::sha256_instance_def::{
    CELLS_PER_SHA256, INPUT_CELLS_PER_SHA256,
};
use crate::types::relocatable::{MaybeRelocatable, Relocatable};
use crate::vm::errors::memory_errors::MemoryError;
use crate::vm::errors::runner_errors::RunnerError;
use crate::vm::vm_memory::memory::Memory;
use crate::vm::vm_memory::memory_segments::MemorySegmentManager;
use crate::Felt252;
use num_integer::div_ceil;
use num_traits::ToPrimitive;

#[derive(Debug, Clone)]
pub struct Sha256BuiltinRunner {
    pub base: usize,
    ratio: Option<u32>,
    pub(crate) stop_ptr: Option<usize>,
    pub(crate) included: bool,
    cache: RefCell<HashMap<Relocatable, Felt252>>,
}

impl Sha256BuiltinRunner {
    pub fn new(ratio: Option<u32>, included: bool) -> Self {
        Sha256BuiltinRunner {
            base: 0,
            ratio,
            stop_ptr: None,
            included,
            cache: RefCell::new(HashMap::new()),
        }
    }

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
        self.ratio
    }

    pub fn add_validation_rule(&self, _memory: &mut Memory) {}

    pub fn deduce_memory_cell(
        &self,
        address: Relocatable,
        memory: &Memory,
    ) -> Result<Option<MaybeRelocatable>, RunnerError> {
        let index = address.offset % CELLS_PER_SHA256 as usize;
        if index < INPUT_CELLS_PER_SHA256 as usize {
            return Ok(None);
        }
        if let Some(felt) = self.cache.borrow().get(&address) {
            return Ok(Some(felt.into()));
        }
        let first_input_addr = (address - index)?;
        let first_output_addr = (first_input_addr + INPUT_CELLS_PER_SHA256 as usize)?;

        let mut input_felts = vec![];

        for i in 0..INPUT_CELLS_PER_SHA256 as usize {
            let m_index = (first_input_addr + i)?;
            let val = match memory.get(&m_index) {
                Some(value) => *value
                    .get_int_ref()
                    .ok_or(RunnerError::BuiltinExpectedInteger(Box::new((
                        BuiltinName::sha256,
                        m_index,
                    ))))?,
                _ => return Ok(None),
            };
            input_felts.push(val)
        }
        // n_input_cells is fixed to 16, so this try_into will never fail
        let sha256_felt: [Felt252; 16] = input_felts.try_into().unwrap();
        let sha256_u32: [u32; 16] = sha256_felt
            .iter()
            .map(|x| x.to_u32().unwrap())
            .collect::<Vec<u32>>()
            .try_into()
            .unwrap();
        let output_u32 = sha256(&sha256_u32);

        for (i, elem) in output_u32.iter().enumerate() {
            self.cache
                .borrow_mut()
                .insert((first_output_addr + i)?, Felt252::from(*elem));
        }

        Ok(self.cache.borrow().get(&address).map(|x| x.into()))
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
        Ok(div_ceil(used_cells, CELLS_PER_SHA256 as usize))
    }

    pub fn air_private_input(&self, memory: &Memory) -> Vec<PrivateInput> {
        let mut private_inputs = vec![];
        if let Some(segment) = memory.data.get(self.base) {
            let segment_len = segment.len();
            for (index, off) in (0..segment_len)
                .step_by(CELLS_PER_SHA256 as usize)
                .enumerate()
            {
                // Add the input cells of each poseidon instance to the private inputs
                if let (
                    Ok(input_s0),
                    Ok(input_s1),
                    Ok(input_s2),
                    Ok(input_s3),
                    Ok(input_s4),
                    Ok(input_s5),
                    Ok(input_s6),
                    Ok(input_s7),
                    Ok(input_s8),
                    Ok(input_s9),
                    Ok(input_s10),
                    Ok(input_s11),
                    Ok(input_s12),
                    Ok(input_s13),
                    Ok(input_s14),
                    Ok(input_s15),
                ) = (
                    memory.get_integer((self.base as isize, off).into()),
                    memory.get_integer((self.base as isize, off + 1).into()),
                    memory.get_integer((self.base as isize, off + 2).into()),
                    memory.get_integer((self.base as isize, off + 3).into()),
                    memory.get_integer((self.base as isize, off + 4).into()),
                    memory.get_integer((self.base as isize, off + 5).into()),
                    memory.get_integer((self.base as isize, off + 6).into()),
                    memory.get_integer((self.base as isize, off + 7).into()),
                    memory.get_integer((self.base as isize, off + 8).into()),
                    memory.get_integer((self.base as isize, off + 9).into()),
                    memory.get_integer((self.base as isize, off + 10).into()),
                    memory.get_integer((self.base as isize, off + 11).into()),
                    memory.get_integer((self.base as isize, off + 12).into()),
                    memory.get_integer((self.base as isize, off + 13).into()),
                    memory.get_integer((self.base as isize, off + 14).into()),
                    memory.get_integer((self.base as isize, off + 15).into()),
                ) {
                    private_inputs.push(PrivateInput::Sha256State(PrivateInputSha256State {
                        index,
                        input_s0: *input_s0,
                        input_s1: *input_s1,
                        input_s2: *input_s2,
                        input_s3: *input_s3,
                        input_s4: *input_s4,
                        input_s5: *input_s5,
                        input_s6: *input_s6,
                        input_s7: *input_s7,
                        input_s8: *input_s8,
                        input_s9: *input_s9,
                        input_s10: *input_s10,
                        input_s11: *input_s11,
                        input_s12: *input_s12,
                        input_s13: *input_s13,
                        input_s14: *input_s14,
                        input_s15: *input_s15,
                    }))
                }
            }
        }
        private_inputs
    }
}

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];
pub fn sha256(input: &[u32; 16]) -> [u32; 8] {
    let mut wis = [0; 64];
    let mut a: u32 = 0x6a09e667;
    let mut b: u32 = 0xbb67ae85;
    let mut c: u32 = 0x3c6ef372;
    let mut d: u32 = 0xa54ff53a;
    let mut e: u32 = 0x510e527f;
    let mut f: u32 = 0x9b05688c;
    let mut g: u32 = 0x1f83d9ab;
    let mut h: u32 = 0x5be0cd19;
    wis[..16].copy_from_slice(input);
    for t in 16..64 {
        let term1 = _sigma1(wis[t - 2]);
        let term2 = wis[t - 7];
        let term3 = _sigma0(wis[t - 15]);
        let term4 = wis[t - 16];
        wis[t] = term1
            .wrapping_add(term2)
            .wrapping_add(term3)
            .wrapping_add(term4);
    }

    for t in 0..64 {
        let t1 = h
            .wrapping_add(_capsigma1(e))
            .wrapping_add(_ch(e, f, g))
            .wrapping_add(K[t])
            .wrapping_add(wis[t]);

        let t2 = _capsigma0(a).wrapping_add(_maj(a, b, c));

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    [a, b, c, d, e, f, g, h]
}

fn _sigma0(num: u32) -> u32 {
    num.rotate_right(7) ^ num.rotate_right(18) ^ (num >> 3)
}
fn _sigma1(num: u32) -> u32 {
    num.rotate_right(17) ^ num.rotate_right(19) ^ (num >> 10)
}

fn _capsigma0(num: u32) -> u32 {
    num.rotate_right(2) ^ num.rotate_right(13) ^ num.rotate_right(22)
}
fn _capsigma1(num: u32) -> u32 {
    num.rotate_right(6) ^ num.rotate_right(11) ^ num.rotate_right(25)
}

fn _ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

fn _maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}
