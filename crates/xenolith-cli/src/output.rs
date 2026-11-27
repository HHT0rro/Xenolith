//! Stage user data beside its destination before publishing it.

use anyhow::{bail, ensure, Context, Result};
use std::fs::{self, File, Metadata, OpenOptions, Permissions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;

pub struct Output {
    destination: PathBuf,
    requested: PathBuf,
}

impl Output {
    pub fn new(path: &Path, protected: &[&Path]) -> Result<Self> {
        let requested = path.to_path_buf();
        let path = entry_path(path).with_context(|| format!("output {}", path.display()))?;
        let existing = regular_entry(&path)?;
        for source in protected.iter().filter(|p| !p.as_os_str().is_empty()) {
            let same_path = match entry_path(source) {
                Ok(source) => same_path(&path, &source),
                Err(e) if e.kind() == io::ErrorKind::NotFound => false,
                Err(e) => {
                    return Err(e).with_context(|| format!("check path {}", source.display()))
                }
            };
            if same_path || (existing.is_some() && aliases(&path, source)?) {
                bail!(
                    "output {} refers to the same file as {}",
                    path.display(),
                    source.display()
                );
            }
        }
        Ok(Self {
            destination: path,
            requested,
        })
    }

    pub fn path(&self) -> &Path {
        &self.destination
    }

    pub fn requested_path(&self) -> &Path {
        &self.requested
    }

    pub fn require_new(&self) -> Result<()> {
        ensure!(
            regular_entry(self.path())?.is_none(),
            "output {} already exists; choose a different path",
            self.requested.display()
        );
        Ok(())
    }

    pub fn write_new(&self, bytes: &[u8], permissions: Option<&Permissions>) -> Result<()> {
        self.require_new()?;
        let mut temp = self.stage(bytes, permissions)?;
        // The publication itself must refuse to clobber a file that appeared
        // after the preflight check, including while a pack was running.
        publish_new(&mut temp, self.path())
            .with_context(|| format!("create {} without overwriting", self.requested.display()))
    }

    pub fn write_project_update(
        &self,
        bytes: &[u8],
        validate_existing: impl FnOnce(&mut File) -> Result<()>,
    ) -> Result<()> {
        let Some(before) = regular_entry(self.path())? else {
            return self.write_new(bytes, None);
        };
        ensure!(
            !before.permissions().readonly(),
            "project {} is read-only",
            self.requested.display()
        );
        let mut existing = File::open(self.path())
            .with_context(|| format!("open project {}", self.requested.display()))?;
        let id = file_id(&existing)?;
        #[cfg(unix)]
        ensure!(
            id == (before.dev(), before.ino()),
            "project {} changed before saving",
            self.requested.display()
        );
        validate_existing(&mut existing)
            .with_context(|| format!("refusing to overwrite {}", self.requested.display()))?;
        let mut temp = self.stage(bytes, Some(&before.permissions()))?;
        let unchanged = if let Some(now) = regular_entry(self.path())? {
            let current = File::open(self.path())?;
            file_id(&current)? == id
                && now.len() == before.len()
                && now.modified()? == before.modified()?
                && now.permissions() == before.permissions()
        } else {
            false
        };
        ensure!(
            unchanged,
            "project {} changed before saving",
            self.requested.display()
        );
        fs::rename(&temp.path, self.path())
            .with_context(|| format!("replace project {}", self.requested.display()))?;
        temp.moved = true;
        Ok(())
    }

    fn stage(&self, bytes: &[u8], permissions: Option<&Permissions>) -> Result<TempFile> {
        let (temp, mut file) = TempFile::new(self.path())
            .with_context(|| format!("stage {}", self.requested.display()))?;
        (|| -> io::Result<()> {
            file.write_all(bytes)?;
            #[cfg(unix)]
            if let Some(permissions) = permissions {
                // Carry ordinary rwx bits, never setuid/setgid or sticky bits.
                file.set_permissions(Permissions::from_mode(permissions.mode() & 0o777))?;
            }
            #[cfg(not(unix))]
            let _ = permissions;
            file.sync_all()
        })()
        .with_context(|| format!("write staged file for {}", self.requested.display()))?;
        Ok(temp)
    }
}

pub fn read_input(path: &Path) -> Result<(Vec<u8>, Permissions)> {
    (|| -> io::Result<_> {
        #[cfg(windows)]
        check_windows_path(path)?;
        if !fs::metadata(path)?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "input is not a regular file",
            ));
        }
        let mut file = File::open(path)?;
        let permissions = file.metadata()?.permissions();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok((bytes, permissions))
    })()
    .with_context(|| format!("read {}", path.display()))
}

/// Canonicalize the parent only. The destination entry itself must never be followed.
fn entry_path(path: &Path) -> io::Result<PathBuf> {
    let raw = path.as_os_str().as_encoded_bytes();
    let leaf = raw
        .rsplit(|b| std::path::is_separator(char::from(*b)))
        .next();
    if matches!(leaf, Some(b"" | b"." | b"..")) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected a file name",
        ));
    }
    #[cfg(windows)]
    check_windows_path(path)?;
    let path = std::path::absolute(path)?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "expected a file name"))?;
    Ok(path
        .parent()
        .expect("absolute file path has a parent")
        .canonicalize()?
        .join(name))
}

#[cfg(windows)]
fn check_windows_path(path: &Path) -> io::Result<()> {
    use std::path::{Component, Prefix};

    // Exclude device namespaces, alternate data streams, and names Win32 can
    // silently trim before opening. Verbatim disk and UNC paths remain valid.
    for component in path.components() {
        let invalid = match component {
            Component::Prefix(p) => matches!(p.kind(), Prefix::DeviceNS(_) | Prefix::Verbatim(_)),
            Component::Normal(component) => {
                let bytes = component.as_encoded_bytes();
                bytes.contains(&b':')
                    || bytes.ends_with(b".")
                    || bytes.ends_with(b" ")
                    || windows_device_name(component)
            }
            _ => false,
        };
        if invalid {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ambiguous Windows file path",
            ));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn windows_device_name(name: &std::ffi::OsStr) -> bool {
    let name = name.to_string_lossy();
    let stem = name
        .split('.')
        .next()
        .unwrap_or_default()
        .trim_end_matches(' ');
    let stem = stem.to_ascii_uppercase();
    matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || matches!(
        stem.strip_prefix("COM")
            .or_else(|| stem.strip_prefix("LPT")),
        Some("1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "\u{b9}" | "\u{b2}" | "\u{b3}")
    )
}

fn same_path(a: &Path, b: &Path) -> bool {
    #[cfg(windows)]
    return a.to_string_lossy().to_uppercase() == b.to_string_lossy().to_uppercase();
    #[cfg(not(windows))]
    return a == b;
}

fn regular_entry(path: &Path) -> Result<Option<Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            #[cfg(windows)]
            let reparse = meta.file_attributes() & 0x400 != 0; // FILE_ATTRIBUTE_REPARSE_POINT
            #[cfg(not(windows))]
            let reparse = false;
            ensure!(
                meta.is_file() && !reparse,
                "refusing output {}: expected a regular file, not a link or special file",
                path.display()
            );
            Ok(Some(meta))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("check output {}", path.display())),
    }
}

fn aliases(destination: &Path, source: &Path) -> Result<bool> {
    let source = match fs::metadata(source) {
        Ok(meta) if meta.is_file() => source,
        Ok(_) => return Ok(false),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e).with_context(|| format!("check {}", source.display())),
    };
    (|| -> io::Result<bool> {
        Ok(file_id(&File::open(destination)?)? == file_id(&File::open(source)?)?)
    })()
    .with_context(|| format!("compare {} and {}", destination.display(), source.display()))
}

#[cfg(unix)]
fn file_id(file: &File) -> io::Result<(u64, u64)> {
    let meta = file.metadata()?;
    Ok((meta.dev(), meta.ino()))
}

#[cfg(windows)]
fn file_id(file: &File) -> io::Result<(u64, [u8; 16])> {
    use std::os::windows::io::AsRawHandle;

    #[repr(C)]
    struct FileIdInfo {
        volume_serial_number: u64,
        file_id: [u8; 16],
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetFileInformationByHandleEx(
            file: std::os::windows::io::RawHandle,
            class: i32,
            info: *mut FileIdInfo,
            size: u32,
        ) -> i32;
    }
    let mut info = FileIdInfo {
        volume_serial_number: 0,
        file_id: [0; 16],
    };
    // SAFETY: The File keeps the handle live and the buffer matches FILE_ID_INFO.
    const FILE_ID_INFO_CLASS: i32 = 18; // FILE_INFO_BY_HANDLE_CLASS::FileIdInfo
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FILE_ID_INFO_CLASS,
            &mut info,
            std::mem::size_of::<FileIdInfo>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok((info.volume_serial_number, info.file_id))
}

#[cfg(not(windows))]
fn publish_new(temp: &mut TempFile, destination: &Path) -> io::Result<()> {
    fs::hard_link(&temp.path, destination)
}

#[cfg(windows)]
fn publish_new(temp: &mut TempFile, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    #[link(name = "kernel32")]
    extern "system" {
        fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
    }
    let wide =
        |path: &Path| -> Vec<u16> { path.as_os_str().encode_wide().chain(Some(0)).collect() };
    let source = wide(&temp.path);
    let destination = wide(destination);
    // SAFETY: Both paths are live, NUL-terminated UTF-16 buffers. Flags 0
    // leave replacement and cross-volume copy disabled.
    if unsafe { MoveFileExW(source.as_ptr(), destination.as_ptr(), 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    temp.moved = true;
    Ok(())
}

struct TempFile {
    path: PathBuf,
    moved: bool,
}

impl TempFile {
    fn new(destination: &Path) -> io::Result<(Self, File)> {
        let dir = destination.parent().expect("validated output parent");
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        for _ in 0..128 {
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = dir.join(format!(".xenolith-{}-{n}.tmp", std::process::id()));
            if same_path(&path, destination) {
                continue;
            }
            match options.open(&path) {
                Ok(file) => return Ok((Self { path, moved: false }, file)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not reserve a temporary file",
        ))
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if !self.moved {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) struct TestDir(pub PathBuf);

    impl TestDir {
        pub(crate) fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            loop {
                let n = NEXT.fetch_add(1, Ordering::Relaxed);
                let path =
                    std::env::temp_dir().join(format!("xenolith-p0-{}-{n}", std::process::id()));
                match fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(e) => panic!("create {}: {e}", path.display()),
                }
            }
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn rejects_direct_and_hard_link_aliases() {
        let dir = TestDir::new();
        let input = dir.0.join("original.dat");
        let alias = dir.0.join("other-name.dat");
        fs::write(&input, b"original").unwrap();
        fs::hard_link(&input, &alias).unwrap();
        for out in [&input, &alias, &dir.0.join("./original.dat")] {
            let err = Output::new(out, &[&input]).err().unwrap();
            assert!(err.to_string().contains("same file"), "{err:#}");
        }
        assert_eq!(fs::read(input).unwrap(), b"original");
        assert_eq!(fs::read(alias).unwrap(), b"original");
    }

    #[test]
    fn existing_output_is_preserved_even_if_it_appears_after_staging() {
        let dir = TestDir::new();
        let path = dir.0.join("output.dat");
        let output = Output::new(&path, &[]).unwrap();
        let mut temp = output.stage(b"candidate", None).unwrap();
        assert!(!path.exists());
        fs::write(&path, b"other writer").unwrap();
        assert!(publish_new(&mut temp, output.path()).is_err());
        drop(temp);
        assert!(output.write_new(b"candidate", None).is_err());
        assert_eq!(fs::read(path).unwrap(), b"other writer");
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 1);
    }

    #[test]
    fn explicit_replacement_rechecks_destination_after_validation() {
        let dir = TestDir::new();
        let path = dir.0.join("project.json");
        let old_path = dir.0.join("old.json");
        fs::write(&path, b"original").unwrap();
        let output = Output::new(&path, &[]).unwrap();
        let err = output
            .write_project_update(b"new contents", |_| {
                fs::rename(&path, &old_path)?;
                fs::write(&path, b"different file")?;
                Ok(())
            })
            .unwrap_err();
        assert!(err.to_string().contains("changed before saving"), "{err:#}");
        assert_eq!(fs::read(&old_path).unwrap(), b"original");
        assert_eq!(fs::read(&path).unwrap(), b"different file");
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 2);
    }

    #[cfg(windows)]
    #[test]
    fn windows_path_alias_and_blocked_replace_leave_original() {
        use std::os::windows::fs::OpenOptionsExt;

        let dir = TestDir::new();
        let path = dir.0.join("project.json");
        fs::write(&path, b"original").unwrap();
        assert!(Output::new(&dir.0.join("PROJECT.json"), &[&path]).is_err());
        assert!(Output::new(&dir.0.join("project.json:stream"), &[]).is_err());
        assert!(Output::new(&dir.0.join("NUL.txt"), &[]).is_err());
        let lock = OpenOptions::new()
            .read(true)
            .share_mode(3)
            .open(&path)
            .unwrap();
        let output = Output::new(&path, &[]).unwrap();
        assert!(output.write_project_update(b"new", |_| Ok(())).is_err());
        drop(lock);
        assert_eq!(fs::read(&path).unwrap(), b"original");
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_and_special_destinations_are_rejected() {
        use std::os::unix::fs::symlink;

        let dir = TestDir::new();
        let input = dir.0.join("image");
        fs::write(&input, b"original").unwrap();
        let linked_dir = dir.0.join("linked-dir");
        symlink(&dir.0, &linked_dir).unwrap();
        assert!(Output::new(&linked_dir.join("image"), &[&input]).is_err());
        let linked_file = dir.0.join("linked-file");
        symlink(&input, &linked_file).unwrap();
        assert!(Output::new(&linked_file, &[]).is_err());
        let missing = dir.0.join("missing");
        let dangling = dir.0.join("dangling");
        symlink(&missing, &dangling).unwrap();
        assert!(Output::new(&dangling, &[]).is_err());
        assert!(Output::new(&dir.0, &[]).is_err());
        assert_eq!(fs::read(input).unwrap(), b"original");
        assert!(!missing.exists());
    }

    #[cfg(unix)]
    #[test]
    fn publication_preserves_rwx_bits_and_strips_special_mode_bits() {
        let dir = TestDir::new();
        let input = dir.0.join("input");
        let image = dir.0.join("output");
        let config = dir.0.join("project.json");
        fs::write(&input, b"original").unwrap();
        fs::set_permissions(&input, Permissions::from_mode(0o6751)).unwrap();
        let (_, mode) = read_input(&input).unwrap();
        Output::new(&image, &[&input])
            .unwrap()
            .write_new(b"packed", Some(&mode))
            .unwrap();
        assert_eq!(fs::metadata(&image).unwrap().mode() & 0o7777, 0o751);

        let output = Output::new(&config, &[]).unwrap();
        output.write_new(b"original", None).unwrap();
        assert_eq!(fs::metadata(&config).unwrap().mode() & 0o177, 0);
        fs::set_permissions(&config, Permissions::from_mode(0o640)).unwrap();
        output.write_project_update(b"updated", |_| Ok(())).unwrap();
        assert_eq!(fs::read(&config).unwrap(), b"updated");
        assert_eq!(fs::metadata(&config).unwrap().mode() & 0o7777, 0o640);
    }
}
