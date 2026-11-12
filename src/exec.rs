//! Command execution semantics shared by every guest OS.
//!
//! SSH transports an exit status as a `uint32`, while [`std::process::ExitStatus`] can
//! only report `0..=255`. Silently truncating (or reinterpreting) the value would make a
//! failed command look successful, so the conversion lives in one place.

use std::{os::unix::process::ExitStatusExt, process::ExitStatus};

use anyhow::{Result, bail};

/// Highest exit code that [`std::process::ExitStatus`] can report.
pub(crate) const MAX_EXIT_CODE: u32 = 255;

/// Convert an SSH exit-status into the [`ExitStatus`] reported to callers.
///
/// `status.success()` is true only for `0`, and `status.code()` returns `0..=255`
/// unchanged. Anything outside that range is rejected with an actionable error instead of
/// being truncated; Windows reports failures such as `0xC0000005`, which have no
/// representable `ExitStatus`.
pub(crate) fn exit_status_from_code(command: &str, code: u32) -> Result<ExitStatus> {
    if code > MAX_EXIT_CODE {
        bail!(
            "command exited with status {code}, which cannot be represented as an exit status \
             (supported range 0..={MAX_EXIT_CODE}).\n\
             The raw status was reported for `{command}`; inspect its output instead."
        );
    }

    // `ExitStatus::from_raw` takes a wait status, not an exit code, so the code must be
    // shifted into the high byte. Linux guests previously passed the code straight
    // through, which made every non-zero exit look successful.
    Ok(std::process::ExitStatus::from_raw((code << 8) as i32))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_exec_zero_exit_is_success() {
        let status = exit_status_from_code("cmd /c ver", 0).expect("code 0 is representable");
        assert!(status.success());
        assert_eq!(status.code(), Some(0));
    }

    #[test]
    fn windows_exec_non_zero_exit_is_failure() {
        let status = exit_status_from_code("cmd /c exit 1", 1).expect("code 1 is representable");
        assert!(!status.success());
        assert_eq!(status.code(), Some(1));
    }

    #[test]
    fn windows_exec_keeps_codes_up_to_255() {
        for code in [2u32, 127, 128, 254, MAX_EXIT_CODE] {
            let status = exit_status_from_code("exit", code).expect("code is representable");
            assert!(
                !status.success(),
                "code {code} must not be reported as success"
            );
            assert_eq!(status.code(), Some(code as i32));
        }
    }

    #[test]
    fn windows_exec_rejects_unrepresentable_exit_code() {
        let err = exit_status_from_code("cmd /c exit 300", 300)
            .expect_err("300 is not representable")
            .to_string();
        assert!(err.contains("300"), "{err}");
        assert!(err.contains("0..=255"), "{err}");
        assert!(err.contains("cmd /c exit 300"), "{err}");
    }

    #[test]
    fn windows_exec_rejects_windows_failure_status_without_truncating() {
        // 0xC0000005 (access violation) truncates to 5, which would look like a
        // legitimate small exit code, so it must be rejected instead.
        let err = exit_status_from_code("cmd /c crash", 0xC000_0005)
            .expect_err("large Windows status is not representable")
            .to_string();
        assert!(err.contains("3221225477"), "{err}");
    }
}
