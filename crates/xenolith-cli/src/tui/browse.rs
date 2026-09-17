//! Directory listing for the Pick screen. Pure functions, fail-closed.

use std::io;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirRow {
    pub name: String,
    pub path: PathBuf,
    pub is_dir: bool,
}

/// Anything the Pick screen opens: PE (`*.dll`/`*.exe`), ELF
/// (`*.so`/`*.elf`), or a saved project (`*.xenolith.json`).
pub fn is_pickable_name(name: &str) -> bool {
    let p = Path::new(name);
    let ext = p
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase());
    match ext.as_deref() {
        Some("dll") | Some("exe") | Some("so") | Some("elf") => true,
        Some("json") => {
            let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            stem.to_ascii_lowercase().ends_with(".xenolith")
        }
        _ => false,
    }
}

/// Parent directory for `..`. `None` at a Unix root, a Windows drive root (`C:\`),
/// or an empty parent.
pub fn parent_of(path: &Path) -> Option<PathBuf> {
    use std::path::Component;
    let parent = path.parent()?;
    if parent.as_os_str().is_empty() {
        return None;
    }
    let comps: Vec<_> = path.components().collect();
    if comps.len() <= 1 {
        return None;
    }
    if comps.len() == 2
        && matches!(comps[0], Component::Prefix(_))
        && matches!(comps[1], Component::RootDir)
    {
        return None;
    }
    Some(parent.to_path_buf())
}

/// `..` (when not at a root) + subdirectories + files `is_pickable_name`
/// accepts (PE, ELF, project JSON). Directories first, then case-insensitive
/// name. `read_dir` errors propagate; unreadable individual entries are skipped.
pub fn read_dir_sorted(cwd: &Path) -> io::Result<Vec<DirRow>> {
    let mut rows = Vec::new();
    if let Some(parent) = parent_of(cwd) {
        rows.push(DirRow {
            name: "..".into(),
            path: parent,
            is_dir: true,
        });
    }
    let mut rest = Vec::new();
    for ent in std::fs::read_dir(cwd)? {
        let ent = match ent {
            Ok(e) => e,
            Err(_) => continue,
        };
        let name = ent.file_name().to_string_lossy().into_owned();
        if name == "." || name == ".." {
            continue;
        }
        let ft = match ent.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        let is_dir = ft.is_dir();
        if !is_dir && !is_pickable_name(&name) {
            continue;
        }
        rest.push(DirRow {
            path: ent.path(),
            name,
            is_dir,
        });
    }
    rest.sort_by(|a, b| match (a.is_dir, b.is_dir) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a
            .name
            .to_ascii_lowercase()
            .cmp(&b.name.to_ascii_lowercase()),
    });
    rows.extend(rest);
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn unique_dir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "xl-browse-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn pickable_names_are_pe_elf_project() {
        for ok in [
            "a.dll",
            "B.EXE",
            "lib.so",
            "x.SO",
            "app.elf",
            "p.xenolith.json",
            "P.XENOLITH.JSON",
        ] {
            assert!(is_pickable_name(ok), "{ok}");
        }
        for bad in [
            "notes.txt",
            "a.dll.bak",
            "dll",
            "other.json",
            "xenolith.json",
            "a.xenolith.json.bak",
        ] {
            assert!(!is_pickable_name(bad), "{bad}");
        }
    }

    #[test]
    fn parent_of_empty_is_none() {
        assert!(parent_of(Path::new("")).is_none());
        assert!(parent_of(Path::new("/")).is_none());
    }

    #[cfg(windows)]
    #[test]
    fn windows_drive_root_has_no_parent() {
        assert!(parent_of(Path::new(r"C:\")).is_none());
        assert_eq!(
            parent_of(Path::new(r"C:\foo")).as_deref(),
            Some(Path::new(r"C:\"))
        );
    }

    #[test]
    fn lists_dirs_first_then_pickable_skips_other_files() {
        let root = unique_dir("sort");
        fs::create_dir_all(root.join("sub")).unwrap();
        fs::create_dir_all(root.join("Aaa")).unwrap();
        fs::write(root.join("z.dll"), b"").unwrap();
        fs::write(root.join("B.EXE"), b"").unwrap();
        fs::write(root.join("notes.txt"), b"nope").unwrap();
        fs::write(root.join("lib.so"), b"").unwrap();
        fs::write(root.join("app.elf"), b"").unwrap();
        fs::write(root.join("p.xenolith.json"), b"{}").unwrap();
        fs::write(root.join("other.json"), b"{}").unwrap();

        let rows = read_dir_sorted(&root).unwrap();
        let names: Vec<&str> = rows.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&".."), "{names:?}");
        assert!(!names.contains(&"notes.txt"), "{names:?}");
        assert!(!names.contains(&"other.json"), "{names:?}");
        for listed in ["lib.so", "app.elf", "p.xenolith.json"] {
            assert!(names.contains(&listed), "{names:?}");
        }

        let rest: Vec<&DirRow> = rows.iter().filter(|r| r.name != "..").collect();
        assert!(rest[0].is_dir && rest[1].is_dir, "{names:?}");
        let dir_names: Vec<&str> = rest
            .iter()
            .filter(|r| r.is_dir)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(dir_names, vec!["Aaa", "sub"]);
        let files: Vec<&str> = rest
            .iter()
            .filter(|r| !r.is_dir)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(
            files,
            vec![
                "app.elf",
                "B.EXE",
                "lib.so",
                "p.xenolith.json",
                "z.dll"
            ]
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_dir_is_error() {
        let p = unique_dir("gone");
        let _ = fs::remove_dir_all(&p);
        assert!(read_dir_sorted(&p).is_err());
    }
}
