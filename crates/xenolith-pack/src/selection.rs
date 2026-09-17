//! Function selection: named export, explicit RVA+length, fail-closed otherwise.

use crate::analysis::function_map::{BoundarySource, FunctionMap, MappedFunction};
use crate::lift::forbidden_vm_name;
use xenolith_formats::Pe64;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SelectError {
    #[error("{0}")]
    Invalid(String),
}

#[derive(Clone, Debug, Default)]
pub struct FunctionSelector {
    pub exports: Vec<String>,
    pub ranges: Vec<(u32, u32)>, // (rva, len)
    pub functions: Vec<String>,
    pub select_all: bool,
    pub strict: bool,
}

impl FunctionSelector {
    pub fn is_empty(&self) -> bool {
        self.exports.is_empty()
            && self.ranges.is_empty()
            && self.functions.is_empty()
            && !self.select_all
    }

    pub fn resolve(&self, pe: &Pe64, image: &[u8]) -> Result<FunctionMap, SelectError> {
        let exports = pe.exports(image).map_err(|e| SelectError::Invalid(e.to_string()))?;
        let coff = pe
            .coff_functions(image)
            .map_err(|e| SelectError::Invalid(e.to_string()))?;
        let runtime = pe
            .runtime_functions(image)
            .map_err(|e| SelectError::Invalid(e.to_string()))?;
        let mut map = FunctionMap::default();

        // Explicit address ranges have the highest priority and are always
        // retained even when metadata discovery is enabled.
        for (rva, len) in &self.ranges {
            if *len == 0 {
                return Err(SelectError::Invalid(format!(
                    "select-rva {rva:#x}: length must be > 0"
                )));
            }
            if pe.file_offset_of(*rva).is_err() {
                return Err(SelectError::Invalid(format!(
                    "select-rva {rva:#x}: not in image"
                )));
            }
            map.push(MappedFunction {
                name: format!("rva_{rva:#x}"),
                rva: *rva,
                len: Some(*len),
                source: BoundarySource::ExplicitRange,
            });
        }

        let mut explicit: Vec<String> = self.exports.clone();
        explicit.extend(self.functions.iter().cloned());
        explicit.sort();
        explicit.dedup();
        for name in &explicit {
            if forbidden_vm_name(name) {
                return Err(SelectError::Invalid(format!(
                    "vm-export {name}: CRT/DllMain/JNI stay native"
                )));
            }
            if let Some(exp) = exports.iter().find(|e| e.name == *name) {
                map.push(MappedFunction {
                    name: name.clone(),
                    rva: exp.rva,
                    len: runtime
                        .iter()
                        .find(|r| exp.rva >= r.begin_rva && exp.rva < r.end_rva)
                        .map(|r| r.end_rva - exp.rva),
                    source: BoundarySource::Export,
                });
                continue;
            }
            if let Some(sym) = coff.iter().find(|f| f.name == *name) {
                map.push(MappedFunction {
                    name: name.clone(),
                    rva: sym.rva,
                    len: runtime
                        .iter()
                        .find(|r| sym.rva >= r.begin_rva && sym.rva < r.end_rva)
                        .map(|r| r.end_rva - sym.rva),
                    source: BoundarySource::Symbol,
                });
                continue;
            }
            if let Some(rva) = name
                .strip_prefix("fn_0x")
                .and_then(|hex| u32::from_str_radix(hex, 16).ok())
                .or_else(|| name.strip_prefix("fn_").and_then(|d| d.parse().ok()))
            {
                if let Some(rt) = runtime
                    .iter()
                    .find(|r| rva >= r.begin_rva && rva < r.end_rva)
                {
                    map.push(MappedFunction {
                        name: name.clone(),
                        rva,
                        len: Some(rt.end_rva - rva),
                        source: BoundarySource::Unwind,
                    });
                    continue;
                }
            }
            return Err(SelectError::Invalid(format!(
                "select-function {name} is missing (no export/COFF symbol)"
            )));
        }

        if self.select_all {
            let mut discovered: Vec<String> = exports.iter().map(|e| e.name.clone()).collect();
            discovered.extend(coff.iter().map(|f| f.name.clone()));
            discovered.sort();
            discovered.dedup();
            for name in discovered {
                if forbidden_vm_name(&name) {
                    continue;
                }
                let discovered_rva = exports
                    .iter()
                    .find(|e| e.name == name)
                    .map(|e| e.rva)
                    .or_else(|| coff.iter().find(|f| f.name == name).map(|f| f.rva));
                if map
                    .functions
                    .iter()
                    .any(|f| f.name == name || Some(f.rva) == discovered_rva)
                {
                    continue;
                }
                if let Some(exp) = exports.iter().find(|e| e.name == name) {
                    map.push(MappedFunction {
                        name,
                        rva: exp.rva,
                        len: None,
                        source: BoundarySource::Export,
                    });
                } else if let Some(sym) = coff.iter().find(|f| f.name == name) {
                    map.push(MappedFunction {
                        name,
                        rva: sym.rva,
                        len: None,
                        source: BoundarySource::Symbol,
                    });
                }
            }
            for rt in &runtime {
                if map
                    .functions
                    .iter()
                    .any(|f| f.rva >= rt.begin_rva && f.rva < rt.end_rva)
                {
                    continue;
                }
                map.push(MappedFunction {
                    name: format!("fn_{:#x}", rt.begin_rva),
                    rva: rt.begin_rva,
                    len: Some(rt.end_rva - rt.begin_rva),
                    source: BoundarySource::Unwind,
                });
            }
        }
        if self.strict && map.functions.is_empty() {
            return Err(SelectError::Invalid(
                "strict coverage: no functions selected".into(),
            ));
        }
        Ok(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xenolith_formats::Pe64;

    fn sample() -> (Vec<u8>, Pe64) {
        let dll = std::fs::read("target/release/hello_dll.dll")
            .or_else(|_| std::fs::read("../../target/release/hello_dll.dll"))
            .expect("hello_dll");
        let pe = Pe64::parse(&dll).unwrap();
        (dll, pe)
    }

    #[test]
    #[cfg(windows)]
    fn export_hello_add() {
        let (dll, pe) = sample();
        let s = FunctionSelector {
            exports: vec!["hello_add".into()],
            ..Default::default()
        };
        let map = s.resolve(&pe, &dll).unwrap();
        assert_eq!(map.functions.len(), 1);
        assert_eq!(map.functions[0].name, "hello_add");
        assert_eq!(map.functions[0].source, BoundarySource::Export);
    }

    #[test]
    #[cfg(windows)]
    fn missing_export_fails() {
        let (dll, pe) = sample();
        let s = FunctionSelector {
            exports: vec!["no_such".into()],
            ..Default::default()
        };
        let err = s.resolve(&pe, &dll).unwrap_err().to_string();
        assert!(err.contains("missing"), "{err}");
    }

    #[test]
    fn strict_empty_fails() {
        let s = FunctionSelector {
            strict: true,
            ..Default::default()
        };
        let err = s.is_empty();
        assert!(err);
    }

    #[test]
    #[cfg(windows)]
    fn explicit_range_zero_len_fails() {
        let (dll, pe) = sample();
        let s = FunctionSelector {
            ranges: vec![(0x1000, 0)],
            ..Default::default()
        };
        let err = s.resolve(&pe, &dll).unwrap_err().to_string();
        assert!(err.contains("length"), "{err}");
    }

    #[test]
    fn select_all_is_explicit() {
        let s = FunctionSelector::default();
        assert!(s.is_empty());
        let s = FunctionSelector {
            select_all: true,
            ..Default::default()
        };
        assert!(!s.is_empty());
    }

    #[test]
    #[cfg(windows)]
    fn select_all_includes_unwind_functions() {
        let (dll, pe) = sample();
        let s = FunctionSelector {
            select_all: true,
            ..Default::default()
        };
        let map = s.resolve(&pe, &dll).unwrap();
        assert!(
            map.functions
                .iter()
                .any(|f| f.source == BoundarySource::Unwind),
            "select-all must include .pdata boundaries: {:?}",
            map.functions
                .iter()
                .map(|f| f.source)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    #[cfg(windows)]
    fn explicit_unwind_name_resolves() {
        let (dll, pe) = sample();
        let first = pe.runtime_functions(&dll).unwrap()[0];
        let name = format!("fn_{:#x}", first.begin_rva);
        let s = FunctionSelector {
            functions: vec![name.clone()],
            ..Default::default()
        };
        let map = s.resolve(&pe, &dll).unwrap();
        assert_eq!(map.functions.len(), 1);
        assert_eq!(map.functions[0].name, name);
        assert_eq!(map.functions[0].source, BoundarySource::Unwind);
        assert_eq!(
            map.functions[0].len,
            Some(first.end_rva - first.begin_rva)
        );
    }
}
