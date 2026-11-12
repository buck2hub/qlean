//! Guest filesystem paths, validated once and then used by every remote SFTP entry point.
//!
//! Host paths and guest paths are different things: a Windows guest is reached with
//! forward-slash drive paths (`C:/Users/qlean`), a Linux guest with POSIX paths. Building a
//! guest path with the host's `Path::join` silently produces the wrong separator, and
//! treating user input as a host path can escape the intended root. [`GuestPath`] is the
//! single conversion point: it validates and normalizes, and every remote operation in
//! [`crate::machine`] and [`crate::ssh`] consumes it instead of a host path.

use anyhow::{Result, bail};

use crate::image::GuestOs;

/// A validated path inside the guest filesystem.
///
/// Separators are normalized to `/` because that is what both Linux and OpenSSH-on-Windows
/// accept over SFTP; the original spelling (case, spaces, non-ASCII, drive letter) is kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GuestPath {
    guest_os: GuestOs,
    text: String,
}

/// Operations that have no Windows guest equivalent over SFTP.
///
/// They are rejected explicitly: silently doing nothing (or doing something different)
/// would make a Windows machine look like a Linux one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PosixOnlyOperation {
    HardLink,
    ReadLink,
    SetPermissions,
}

impl PosixOnlyOperation {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::HardLink => "hard_link",
            Self::ReadLink => "read_link",
            Self::SetPermissions => "set_permissions",
        }
    }

    fn reason(self) -> &'static str {
        match self {
            Self::HardLink => "Windows has no POSIX hard links",
            Self::ReadLink => "Windows guests do not expose symbolic links over SFTP",
            Self::SetPermissions => "Windows uses ACLs, not POSIX mode bits",
        }
    }
}

/// Reject `operation` for a Windows guest, with the path that triggered it.
pub(crate) fn ensure_supported(
    guest_os: GuestOs,
    operation: PosixOnlyOperation,
    path: &GuestPath,
) -> Result<()> {
    if guest_os == GuestOs::Windows {
        bail!(
            "`{}` is not supported for Windows guests ({}): {}",
            operation.name(),
            path.as_str(),
            operation.reason()
        );
    }
    Ok(())
}

/// Characters Windows refuses in a file or directory name.
const WINDOWS_INVALID_CHARS: [char; 7] = ['<', '>', ':', '"', '|', '?', '*'];

/// Device names Windows reserves regardless of extension or directory.
const WINDOWS_RESERVED_NAMES: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

impl GuestPath {
    /// Validate and normalize `raw` for `guest_os`, reporting unsupported forms.
    pub(crate) fn new(guest_os: GuestOs, raw: impl AsRef<str>) -> Result<Self> {
        let raw = raw.as_ref();
        if raw.trim().is_empty() {
            bail!("guest path must not be empty");
        }
        if raw.contains('\0') {
            bail!("guest path must not contain NUL bytes");
        }

        let text = match guest_os {
            GuestOs::Linux => {
                if raw.starts_with('\\') {
                    bail!(
                        "guest path `{raw}` looks like a Windows path, but this machine runs a Linux guest"
                    );
                }
                raw.to_owned()
            }
            GuestOs::Windows => normalize_windows(raw)?,
        };

        Ok(Self { guest_os, text })
    }

    /// The path as it is sent over SFTP.
    pub(crate) fn as_str(&self) -> &str {
        &self.text
    }

    /// Guest OS this path was validated for.
    pub(crate) fn guest_os(&self) -> GuestOs {
        self.guest_os
    }

    /// Join a single child name, refusing names that would escape the path.
    ///
    /// `child` may come from a host-relative walk (always simple names) or from
    /// [`GuestPath::strip_prefix`]. On Windows both separators spell one thing, so `\` becomes
    /// `/`; on Linux a backslash is an ordinary character in a name and stays one, because the
    /// walk that drives `download`, `upload` and `remove_dir_all` feeds raw entry names through
    /// here. `..` is rejected so a traversal cannot be smuggled in.
    pub(crate) fn join(&self, child: impl AsRef<str>) -> Result<Self> {
        let child = child.as_ref();
        let relative = self.normalize_relative(child)?;
        if relative.is_empty() {
            return Ok(self.clone());
        }

        // A Windows root is spelled "C:", so only the POSIX root trims down to an empty
        // base; that one needs its leading separator restored.
        let base = self.text.trim_end_matches('/');
        let text = if base.is_empty() {
            format!("/{relative}")
        } else {
            format!("{base}/{relative}")
        };

        Self::new(self.guest_os, text)
    }

    /// Parent directory, or `None` at the filesystem root.
    pub(crate) fn parent(&self) -> Option<Self> {
        let trimmed = self.text.trim_end_matches('/');
        match trimmed.rsplit_once('/') {
            // "C:/Users" -> "C:", which is the Windows root spelling.
            Some((head, _)) if head.len() == 2 && head.ends_with(':') => {
                Self::new(self.guest_os, format!("{head}:")).ok()
            }
            Some(("", _)) => Self::new(self.guest_os, "/").ok(),
            Some((head, _)) => Self::new(self.guest_os, head).ok(),
            None => None,
        }
    }

    /// Final component of the path, or `None` at the root.
    pub(crate) fn file_name(&self) -> Option<&str> {
        let trimmed = self.text.trim_end_matches('/');
        let name = trimmed.rsplit('/').next().unwrap_or(trimmed);
        if name.is_empty() || is_root_spelling(name) {
            None
        } else {
            Some(name)
        }
    }

    /// Path prefix for every ancestor, shortest first, for `mkdir -p` style creation.
    pub(crate) fn ancestors(&self) -> Vec<Self> {
        let mut out = Vec::new();
        let mut current = String::new();
        for (index, component) in self.text.split('/').enumerate() {
            if index == 0 {
                // The first segment is the drive ("C:") or empty for a POSIX root.
                if component.is_empty() {
                    current.push('/');
                } else {
                    current.push_str(component);
                }
                out.push(Self::new(self.guest_os, current.clone()).expect("validated prefix"));
                continue;
            }
            if component.is_empty() {
                continue;
            }
            if current != "/" {
                current.push('/');
            }
            current.push_str(component);
            out.push(Self::new(self.guest_os, current.clone()).expect("validated prefix"));
        }
        out
    }

    /// Relative path of `self` under `base`, if it is inside it.
    ///
    /// An empty string means `self` and `base` are the same path.
    pub(crate) fn strip_prefix(&self, base: &GuestPath) -> Option<String> {
        let base_text = base.text.trim_end_matches('/');
        let self_text = self.text.trim_end_matches('/');
        if self_text == base_text {
            return Some(String::new());
        }
        let rest = self_text.strip_prefix(base_text)?;
        Some(rest.strip_prefix('/')?.to_owned())
    }

    /// Whether this path is the guest filesystem root.
    pub(crate) fn is_root(&self) -> bool {
        let trimmed = self.text.trim_end_matches('/');
        trimmed.is_empty() || trimmed == "/" || (trimmed.len() == 2 && trimmed.ends_with(':'))
    }

    fn normalize_relative(&self, child: &str) -> Result<String> {
        let child = match self.guest_os {
            GuestOs::Windows => child.replace('\\', "/"),
            GuestOs::Linux => child.to_owned(),
        };
        if child.starts_with('/') {
            // `Path::join` replaces the base for an absolute argument, so accepting one
            // here would either silently escape the base or silently nest a nonsense
            // path. Neither is what a caller means.
            bail!("cannot join an absolute path onto a guest path: `{child}`");
        }
        let child = child.trim_end_matches('/').to_owned();
        if child.is_empty() {
            return Ok(String::new());
        }

        let mut parts = Vec::new();
        for component in child.split('/') {
            match component {
                "" | "." => continue,
                ".." => bail!("guest path must not contain `..` components: `{child}`"),
                other => parts.push(other),
            }
        }
        let joined = parts.join("/");
        Ok(match self.guest_os {
            GuestOs::Linux => joined,
            GuestOs::Windows => validate_windows_components(&joined)?,
        })
    }
}

fn is_root_spelling(name: &str) -> bool {
    name == "/" || (name.len() == 2 && name.ends_with(':'))
}

/// Normalize a Windows path: drive-absolute, `/` separated, with each component validated.
fn normalize_windows(raw: &str) -> Result<String> {
    // Device paths are checked first: they also start with `\\`, so the UNC branch would
    // otherwise report them as UNC and send the caller looking for a share name.
    if raw.starts_with("\\\\?\\") || raw.starts_with("\\\\.\\") {
        bail!("Windows device paths are not supported: `{raw}`");
    }
    if raw.starts_with("\\\\") || raw.starts_with("//") {
        bail!(
            "UNC paths are not supported for Windows guests: `{raw}`; pass a drive path such as C:/Users/qlean"
        );
    }

    let unified = raw.replace('\\', "/");
    let bytes = unified.as_bytes();
    if bytes.len() < 2 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' {
        bail!(
            "Windows guest paths must start with a drive letter, e.g. C:/Users/qlean (got `{raw}`)"
        );
    }

    let drive = (bytes[0] as char).to_ascii_uppercase();
    let rest = &unified[2..];
    if !rest.is_empty() && !rest.starts_with('/') {
        bail!(
            "drive-relative Windows paths are not supported (got `{raw}`); use a full path such as {drive}:/Users"
        );
    }

    let rest = rest.trim_matches('/');
    if rest.is_empty() {
        return Ok(format!("{drive}:"));
    }

    let components = validate_windows_components(rest)?;
    Ok(format!("{drive}:/{components}"))
}

fn validate_windows_components(path: &str) -> Result<String> {
    for component in path.split('/') {
        if component.is_empty() || component == "." {
            continue;
        }
        if component == ".." {
            bail!("`..` is not allowed in a Windows guest path");
        }
        if component.contains(WINDOWS_INVALID_CHARS) {
            bail!("`{component}` contains a character Windows does not allow in file names");
        }
        if component.chars().any(|c| c.is_control()) {
            bail!("`{component}` contains a control character");
        }
        if component.ends_with(' ') || component.ends_with('.') {
            bail!("`{component}` ends with a space or dot, which Windows strips");
        }
        let stem = component
            .split_once('.')
            .map(|(stem, _)| stem)
            .unwrap_or(component);
        if WINDOWS_RESERVED_NAMES
            .iter()
            .any(|reserved| stem.eq_ignore_ascii_case(reserved))
        {
            bail!("`{component}` is a reserved Windows device name");
        }
    }
    Ok(path.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn win(raw: &str) -> GuestPath {
        GuestPath::new(GuestOs::Windows, raw).expect("valid Windows path")
    }

    fn posix(raw: &str) -> GuestPath {
        GuestPath::new(GuestOs::Linux, raw).expect("valid Linux path")
    }

    #[test]
    fn windows_path_normalizes_drive_root_and_separators() {
        assert_eq!(win(r"C:\Users\qlean").as_str(), "C:/Users/qlean");
        assert_eq!(win("c:/users/qlean").as_str(), "C:/users/qlean");
        assert_eq!(win(r"C:\").as_str(), "C:");
        assert_eq!(win("C:").as_str(), "C:");
        assert!(win("C:").is_root());
        assert_eq!(
            win(r"C:\Program Files\Qlean").as_str(),
            "C:/Program Files/Qlean"
        );
    }

    /// A backslash separates on Windows and is an ordinary character on Linux.
    ///
    /// [`GuestPath::new`] already keeps the spelling it was given, but `join` rewrote every
    /// backslash for every guest, so the walk behind `download`, `upload` and
    /// `remove_dir_all` addressed a Linux file named `a\b` as `a/b` - a different file - and
    /// failed outright on a legal name such as `a\..\b`.
    #[test]
    fn a_linux_guest_keeps_a_backslash_as_an_ordinary_name_character() {
        let dir = posix("/tmp/dir");
        assert_eq!(
            dir.join("a\\b")
                .expect("a backslash is a legal POSIX name")
                .as_str(),
            "/tmp/dir/a\\b"
        );
        assert_eq!(dir.join("a\\b").expect("joined").file_name(), Some("a\\b"));
        assert_eq!(
            dir.join("a\\..\\b").expect("still just a name").as_str(),
            "/tmp/dir/a\\..\\b"
        );

        // Windows is unchanged: both separators mean the same thing there.
        assert_eq!(win("C:/dir").join("a\\b").unwrap().as_str(), "C:/dir/a/b");
        assert_eq!(posix("/").join("a\\b").unwrap().as_str(), "/a\\b");
    }

    #[test]
    fn windows_path_keeps_spaces_and_non_ascii() {
        let path = win(r"C:\Users\qlean\Documents\döner 报告.txt");
        assert_eq!(path.as_str(), "C:/Users/qlean/Documents/döner 报告.txt");
        assert_eq!(path.file_name(), Some("döner 报告.txt"));
    }

    #[test]
    fn windows_path_rejects_unsupported_forms() {
        for raw in [
            r"\\server\share\file",
            "//server/share/file",
            r"\\?\C:\x",
            r"\\.\PhysicalDrive0",
            r"Users\qlean",
            "qlean",
            r"C:relative",
            "",
            "   ",
        ] {
            assert!(
                GuestPath::new(GuestOs::Windows, raw).is_err(),
                "`{raw}` must be rejected"
            );
        }
    }

    #[test]
    fn linux_join_rejects_an_absolute_child() {
        let err = posix("/srv/data")
            .join("/etc/passwd")
            .expect_err("an absolute child must be rejected")
            .to_string();
        assert!(err.contains("absolute"), "{err}");
        // A trailing separator is still just a nested name.
        assert_eq!(
            posix("/srv")
                .join("data/")
                .expect("relative child")
                .as_str(),
            "/srv/data"
        );
    }

    #[test]
    fn windows_device_paths_are_reported_as_device_paths() {
        let err = GuestPath::new(GuestOs::Windows, r"\\?\C:\Users")
            .expect_err("device paths must be rejected")
            .to_string();
        assert!(err.contains("device paths"), "{err}");
    }

    #[test]
    fn windows_join_rejects_an_absolute_child_instead_of_silently_nesting() {
        // `join` must never build `C:/Users/D:/x`: an absolute child would silently
        // become a nonsense path, so the invalid-colon check rejects it.
        let err = win(r"C:\Users")
            .join("D:/data")
            .expect_err("an absolute child must be rejected")
            .to_string();
        assert!(err.contains("does not allow"), "{err}");
    }

    #[test]
    fn windows_path_rejects_invalid_and_reserved_names() {
        for raw in [
            r"C:\Users\a<b",
            r"C:\Users\a|b",
            r"C:\Users\trailing.",
            "C:/Users/trailing ",
            r"C:\Users\CON",
            r"C:\Users\nul.txt",
            "C:/Users/control\u{1}",
        ] {
            assert!(
                GuestPath::new(GuestOs::Windows, raw).is_err(),
                "`{raw}` must be rejected"
            );
        }
    }

    #[test]
    fn windows_path_rejects_traversal() {
        let err = GuestPath::new(GuestOs::Windows, r"C:\Users\..\Windows")
            .expect_err("`..` must be rejected")
            .to_string();
        assert!(err.contains("`..` is not allowed"), "{err}");
        // The diagnostic must not be the trailing-dot rule: Windows strips the dot,
        // it does not treat `..` as a name.
        assert!(!err.contains("ends with a space or dot"), "{err}");

        let base = win(r"C:\Users");
        let err = base
            .join("../Windows")
            .expect_err("joined traversal must be rejected")
            .to_string();
        assert!(err.contains(".."), "{err}");
    }

    #[test]
    fn windows_path_join_and_parent() {
        let base = win(r"C:\Users\qlean");
        assert_eq!(
            base.join("sub dir").unwrap().as_str(),
            "C:/Users/qlean/sub dir"
        );
        assert_eq!(
            base.join(r"sub\deeper").unwrap().as_str(),
            "C:/Users/qlean/sub/deeper"
        );
        assert_eq!(base.parent().unwrap().as_str(), "C:/Users");
        assert!(win("C:").parent().is_none());
        assert!(win("C:").join("Users").unwrap().as_str() == "C:/Users");
    }

    #[test]
    fn windows_path_ancestors_are_incremental() {
        let ancestors = win(r"C:\Users\qlean\Documents")
            .ancestors()
            .iter()
            .map(|p| p.as_str().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            ancestors,
            [
                "C:",
                "C:/Users",
                "C:/Users/qlean",
                "C:/Users/qlean/Documents"
            ]
        );
    }

    #[test]
    fn windows_path_strip_prefix_yields_relative_path() {
        let base = win(r"C:\Users\qlean");
        let deeper = win(r"C:\Users\qlean\Documents\a.txt");
        assert_eq!(deeper.strip_prefix(&base).unwrap(), "Documents/a.txt");
        assert_eq!(deeper.strip_prefix(&deeper).unwrap(), "");
        assert!(base.strip_prefix(&deeper).is_none());
        assert!(win(r"C:\Users\qleanx").strip_prefix(&base).is_none());
    }

    #[test]
    fn windows_path_rejects_posix_only_operations() {
        let path = win(r"C:\Users\qlean\a.txt");
        for operation in [
            PosixOnlyOperation::HardLink,
            PosixOnlyOperation::ReadLink,
            PosixOnlyOperation::SetPermissions,
        ] {
            let err = ensure_supported(GuestOs::Windows, operation, &path)
                .expect_err("POSIX-only operations must be rejected on Windows")
                .to_string();
            assert!(err.contains(operation.name()), "{err}");
            assert!(err.contains("C:/Users/qlean/a.txt"), "{err}");
            assert!(!err.contains('\\'), "{err}");
        }
    }

    #[test]
    fn linux_path_keeps_posix_operations_available() {
        let path = posix("/tmp/a.txt");
        for operation in [
            PosixOnlyOperation::HardLink,
            PosixOnlyOperation::ReadLink,
            PosixOnlyOperation::SetPermissions,
        ] {
            assert!(ensure_supported(GuestOs::Linux, operation, &path).is_ok());
        }
    }

    #[test]
    fn linux_paths_stay_verbatim_and_reject_nul() {
        assert_eq!(posix("/tmp/a b/c").as_str(), "/tmp/a b/c");
        assert_eq!(posix("/").as_str(), "/");
        assert!(GuestPath::new(GuestOs::Linux, "/tmp/\u{0}x").is_err());
        assert!(GuestPath::new(GuestOs::Linux, "").is_err());
        assert_eq!(
            posix("/tmp").join("nested dir").unwrap().as_str(),
            "/tmp/nested dir"
        );
        assert!(posix("/tmp").join("nested/../etc").is_err());
        assert_eq!(posix("/a").parent().unwrap().as_str(), "/");
        let ancestors = posix("/a/b")
            .ancestors()
            .iter()
            .map(|p| p.as_str().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(ancestors, ["/", "/a", "/a/b"]);
    }

    #[test]
    fn windows_paths_hold_structural_invariants_across_spellings() {
        // Every accepted spelling must land on one canonical form and keep the
        // structural helpers consistent with it; the hand-written cases above only
        // cover a few shapes, so this walks the spelling cross-product.
        let components = ["Users", "Program Files", "数据", "a.b", "x-y", "qlean"];
        for drive in ["C", "c", "Z"] {
            for separator in ['/', '\\'] {
                for first in components {
                    for second in components {
                        for third in components {
                            for trailing in [false, true] {
                                let mut raw = format!("{drive}:{separator}{first}");
                                raw.push_str(&format!("{separator}{second}{separator}{third}"));
                                if trailing {
                                    raw.push(separator);
                                }
                                let expected_drive = drive.to_ascii_uppercase();
                                let path = GuestPath::new(GuestOs::Windows, &raw)
                                    .unwrap_or_else(|error| panic!("{raw}: {error}"));
                                let text = path.as_str();
                                assert!(
                                    text.starts_with(&format!("{expected_drive}:/")),
                                    "{raw} -> {text}"
                                );
                                assert!(!text.contains('\\'), "{raw} -> {text}");
                                assert!(!text.contains("//"), "{raw} -> {text}");
                                assert!(!text.ends_with('/'), "{raw} -> {text}");
                                // Re-parsing the canonical form is a no-op.
                                assert_eq!(
                                    GuestPath::new(GuestOs::Windows, text).unwrap().as_str(),
                                    text
                                );
                                assert_eq!(path.file_name(), Some(third));
                                let ancestors = path.ancestors();
                                assert_eq!(
                                    ancestors.first().unwrap().as_str(),
                                    format!("{expected_drive}:")
                                );
                                assert_eq!(ancestors.last().unwrap().as_str(), text);
                                let parent = path.parent().unwrap();
                                assert_eq!(parent.join(third).unwrap().as_str(), text);
                                for ancestor in ancestors {
                                    assert_eq!(
                                        GuestPath::new(GuestOs::Windows, ancestor.as_str())
                                            .unwrap()
                                            .as_str(),
                                        ancestor.as_str()
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn windows_path_rejects_unsupported_shapes_exhaustively() {
        // Each shape must be refused by the check that actually applies to it, so a
        // regression cannot make a case "pass" by failing for an unrelated reason.
        let rejected = [
            ("\\\\server\\share", "UNC paths are not supported"),
            ("//server/share", "UNC paths are not supported"),
            ("\\\\?\\C:\\Users", "device paths are not supported"),
            ("\\\\.\\C:\\Users", "device paths are not supported"),
            ("C:foo", "drive-relative Windows paths are not supported"),
            ("C", "must start with a drive letter"),
            ("", "must not be empty"),
            ("/root", "must start with a drive letter"),
            ("root", "must start with a drive letter"),
            ("C:/Users/..", "`..` is not allowed"),
            ("C:/Users/../../etc", "`..` is not allowed"),
            ("C:/Users\\..\\x", "`..` is not allowed"),
            ("C:/Users/qlean\u{0}", "NUL bytes"),
            ("C:/Users/qlean\u{7}", "control character"),
            ("C:/Users/na<me", "character Windows does not allow"),
            ("C:/Users/na>me", "character Windows does not allow"),
            ("C:/Users/na:me", "character Windows does not allow"),
            ("C:/Users/na\"me", "character Windows does not allow"),
            ("C:/Users/na|me", "character Windows does not allow"),
            ("C:/Users/na?me", "character Windows does not allow"),
            ("C:/Users/na*me", "character Windows does not allow"),
            ("C:/Users/trailing ", "ends with a space or dot"),
            ("C:/Users/trailing.", "ends with a space or dot"),
            ("C:/CON", "reserved Windows device name"),
            ("C:/con.txt", "reserved Windows device name"),
            ("C:/Users/NUL", "reserved Windows device name"),
            ("C:/Users/COM1.log", "reserved Windows device name"),
            ("C:/Users/LPT9", "reserved Windows device name"),
            ("C:/Users/prn.tar.gz", "reserved Windows device name"),
        ];
        for (raw, expected) in rejected {
            let message = GuestPath::new(GuestOs::Windows, raw)
                .err()
                .unwrap_or_else(|| panic!("`{raw}` should be rejected"))
                .to_string();
            assert!(
                message.contains(expected),
                "`{raw}` was rejected with `{message}`, expected `{expected}`"
            );
        }
    }
}
