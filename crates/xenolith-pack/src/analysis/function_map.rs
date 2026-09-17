//! Proven function boundaries and rewrite obligations.

use serde::Serialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BoundarySource {
    Export,
    ExplicitRange,
    Symbol,
    Unwind,
    Pdb,
    Dwarf,
    Cfg,
}

#[derive(Clone, Debug)]
pub struct MappedFunction {
    pub name: String,
    pub rva: u32,
    pub len: Option<u32>,
    pub source: BoundarySource,
}

#[derive(Clone, Debug, Default)]
pub struct FunctionMap {
    pub functions: Vec<MappedFunction>,
}

impl FunctionMap {
    pub fn push(&mut self, f: MappedFunction) {
        if !self.functions.iter().any(|e| e.rva == f.rva && e.name == f.name) {
            self.functions.push(f);
        }
    }
}
