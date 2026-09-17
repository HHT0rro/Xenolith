//! Sparse little-endian memory for MachineState.

use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum MemError {
    #[error("unmapped memory at {0:#x}")]
    Unmapped(u64),
    #[error("misaligned or truncated access at {0:#x}")]
    Bounds(u64),
}

#[derive(Clone, Debug, Default)]
pub struct Memory {
    bytes: BTreeMap<u64, u8>,
}

impl Memory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn write_bytes(&mut self, addr: u64, data: &[u8]) -> Result<(), MemError> {
        for (i, b) in data.iter().enumerate() {
            self.bytes.insert(addr.wrapping_add(i as u64), *b);
        }
        Ok(())
    }

    pub fn read_bytes(&self, addr: u64, len: usize) -> Result<Vec<u8>, MemError> {
        let mut out = Vec::with_capacity(len);
        for i in 0..len {
            let a = addr.wrapping_add(i as u64);
            out.push(*self.bytes.get(&a).ok_or(MemError::Unmapped(a))?);
        }
        Ok(out)
    }

    pub fn read_u64(&self, addr: u64, width: u8) -> Result<u64, MemError> {
        let n = width as usize;
        if n != 1 && n != 2 && n != 4 && n != 8 {
            return Err(MemError::Bounds(addr));
        }
        let bytes = self.read_bytes(addr, n)?;
        let mut v = 0u64;
        for (i, b) in bytes.iter().enumerate() {
            v |= (*b as u64) << (8 * i);
        }
        Ok(v)
    }

    pub fn write_u64(&mut self, addr: u64, width: u8, value: u64) -> Result<(), MemError> {
        let n = width as usize;
        if n != 1 && n != 2 && n != 4 && n != 8 {
            return Err(MemError::Bounds(addr));
        }
        let mut data = vec![0u8; n];
        for i in 0..n {
            data[i] = (value >> (8 * i)) as u8;
        }
        self.write_bytes(addr, &data)
    }
}
