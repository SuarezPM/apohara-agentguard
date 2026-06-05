//! Symlink-resolving path canonicalization with a bounded hop count.
//!
//! Reimplemented from scratch (no external pathsafety dependency). The runner
//! uses [`canonicalize_recursive`] to resolve `workspace_root` and the target
//! workdir to absolute, symlink-free paths before it `chdir`s and applies the
//! Landlock ruleset, and [`is_strict_descendant`] to refuse a workdir that
//! escapes the declared workspace root.
//!
//! Why not `std::fs::canonicalize`? It also resolves symlinks, but it gives no
//! control over the symlink-hop budget. A maliciously deep symlink chain (or a
//! loop) is bounded here by [`MAX_SYMLINK_HOPS`], turning a potential hang /
//! ELOOP surprise into a deterministic, attributable error.

use std::ffi::OsString;
use std::io;
use std::path::{Component, Path, PathBuf};

/// An owned path segment in the work list. Owning the segments (rather than
/// borrowing `Component<'a>` from a temporary `PathBuf`) lets us splice a
/// followed symlink's target into the pending list without lifetime trouble.
enum Seg {
    Root,
    Parent,
    Normal(OsString),
}

/// Convert a path's components into owned [`Seg`]s, dropping `.` segments.
fn to_segs(path: &Path) -> Vec<Seg> {
    path.components()
        .filter_map(|c| match c {
            Component::Prefix(_) | Component::CurDir => None,
            Component::RootDir => Some(Seg::Root),
            Component::ParentDir => Some(Seg::Parent),
            Component::Normal(name) => Some(Seg::Normal(name.to_os_string())),
        })
        .collect()
}

/// Maximum number of symlinks resolved while canonicalizing a single path.
/// Linux's own `MAXSYMLINKS` is 40; we mirror that so behavior matches the
/// kernel's ELOOP threshold.
pub const MAX_SYMLINK_HOPS: usize = 40;

/// Canonicalize `path` to an absolute, symlink-free [`PathBuf`].
///
/// Resolution walks the path component by component, reading and following any
/// symlink encountered, while charging each followed symlink against a shared
/// hop budget of [`MAX_SYMLINK_HOPS`]. Exceeding the budget returns
/// [`io::ErrorKind::FilesystemLoop`]-style `ELOOP`. Every component must exist;
/// a missing component surfaces as `ENOENT`, distinguishing a broken path from
/// a genuine escape attempt.
pub fn canonicalize_recursive(path: &Path) -> io::Result<PathBuf> {
    let mut hops = 0usize;
    let mut resolved = if path.is_absolute() {
        PathBuf::from("/")
    } else {
        std::env::current_dir()?
    };
    // Seed the work list in reverse so we can `pop` cheaply from the back.
    let mut pending: Vec<Seg> = to_segs(path);
    pending.reverse();

    while let Some(seg) = pending.pop() {
        match seg {
            Seg::Root => resolved = PathBuf::from("/"),
            Seg::Parent => {
                resolved.pop();
            }
            Seg::Normal(name) => {
                let candidate = resolved.join(&name);
                let meta = std::fs::symlink_metadata(&candidate)?;
                if meta.file_type().is_symlink() {
                    hops += 1;
                    if hops > MAX_SYMLINK_HOPS {
                        return Err(io::Error::other(format!(
                            "ELOOP: more than {MAX_SYMLINK_HOPS} symlinks while resolving {}",
                            path.display()
                        )));
                    }
                    let target = std::fs::read_link(&candidate)?;
                    // Splice the link target's segments ahead of the rest. An
                    // absolute target resets the accumulator to root.
                    if target.is_absolute() {
                        resolved = PathBuf::from("/");
                    }
                    let mut target_segs = to_segs(&target);
                    target_segs.reverse();
                    pending.append(&mut target_segs);
                } else {
                    resolved = candidate;
                }
            }
        }
    }

    Ok(resolved)
}

/// Returns `true` iff `child` is a strict descendant of `root` (i.e. `child`
/// lives somewhere beneath `root`, and is not `root` itself).
///
/// Both arguments are expected to be already canonicalized; this helper does no
/// I/O and only compares path components, so a `..` segment can never be used to
/// climb above `root` after the fact.
pub fn is_strict_descendant(child: &Path, root: &Path) -> bool {
    if child == root {
        return false;
    }
    child.starts_with(root)
}

// `canonicalize_recursive` is the Linux-sandbox workdir canonicalizer with POSIX
// resolution semantics; the sandbox is Unavailable off-Linux, so its tests run
// only on unix (Linux + macOS), never on Windows.
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;

    fn tmp() -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "agentguard-pathsafe-{}-{}",
            std::process::id(),
            // monotonic-ish unique suffix
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&base).unwrap();
        base
    }

    #[test]
    fn resolves_plain_file() {
        let dir = tmp();
        let f = dir.join("a.txt");
        fs::write(&f, b"x").unwrap();
        let got = canonicalize_recursive(&f).unwrap();
        // The temp dir itself may live under a symlinked /tmp; compare against
        // std::fs::canonicalize which uses the same resolution semantics.
        assert_eq!(got, fs::canonicalize(&f).unwrap());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn follows_single_symlink() {
        let dir = tmp();
        let real = dir.join("real");
        fs::create_dir(&real).unwrap();
        let target = real.join("inner.txt");
        fs::write(&target, b"y").unwrap();
        let link = dir.join("link");
        symlink(&real, &link).unwrap();

        let via_link = link.join("inner.txt");
        let got = canonicalize_recursive(&via_link).unwrap();
        assert_eq!(got, fs::canonicalize(&target).unwrap());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn symlink_loop_hits_hop_cap() {
        let dir = tmp();
        let a = dir.join("a");
        let b = dir.join("b");
        // a -> b, b -> a: any resolution past the cap must error, not hang.
        symlink(&b, &a).unwrap();
        symlink(&a, &b).unwrap();
        let err = canonicalize_recursive(&a).unwrap_err();
        assert!(
            err.to_string().contains("ELOOP"),
            "expected ELOOP error, got: {err}"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_component_is_enoent() {
        let dir = tmp();
        let missing = dir.join("does-not-exist").join("child");
        let err = canonicalize_recursive(&missing).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn strict_descendant_basic() {
        let root = Path::new("/home/u/proj");
        assert!(is_strict_descendant(Path::new("/home/u/proj/src"), root));
        assert!(is_strict_descendant(Path::new("/home/u/proj/a/b"), root));
        // Equal-to-root is NOT a strict descendant.
        assert!(!is_strict_descendant(root, root));
        // Sibling / outside.
        assert!(!is_strict_descendant(Path::new("/home/u/other"), root));
        // Prefix-but-not-component (proj vs projX) must not match.
        assert!(!is_strict_descendant(Path::new("/home/u/projX"), root));
    }

    #[test]
    fn descendant_via_resolved_symlink() {
        let dir = tmp();
        let root = canonicalize_recursive(&dir).unwrap();
        let sub = dir.join("sub");
        fs::create_dir(&sub).unwrap();
        let sub_canon = canonicalize_recursive(&sub).unwrap();
        assert!(is_strict_descendant(&sub_canon, &root));
        fs::remove_dir_all(&dir).ok();
    }
}
