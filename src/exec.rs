//! Command execution semantics shared by every guest OS.
//!
//! SSH transports an exit status as a `uint32`, while [`std::process::ExitStatus`] can
//! only report `0..=255`. Silently truncating (or reinterpreting) the value would make a
//! failed command look successful, so the conversion lives in one place.

use std::{borrow::Cow, os::unix::process::ExitStatusExt, process::ExitStatus};

use anyhow::{Result, bail};

/// Prepare a user command for the guest's configured SSH shell.
///
/// Windows images use PowerShell as OpenSSH's `DefaultShell`. Its implicit
/// `-Command` completion converts every native nonzero exit code to 1. Explicitly
/// exit with the native code instead, so the SSH status still contains e.g. 3 or
/// 300 when it reaches `exit_status_from_code`. PowerShell-only failures have no
/// native exit code and retain status 1; a successful last command returns 0.
/// If a native failure is followed by a nonterminating PowerShell error, the retained
/// nonzero native status wins. Explicit `exit` and terminating errors bypass the epilogue.
///
/// Keep the user's script intact and separate the epilogue with a newline so a
/// trailing comment cannot swallow it. An explicit `exit` in the user's script
/// already exits this same shell and needs no further handling.
pub(crate) fn command_for_guest(guest_os: crate::GuestOs, command: &str) -> Cow<'_, str> {
    match guest_os {
        crate::GuestOs::Linux => Cow::Borrowed(command),
        crate::GuestOs::Windows => Cow::Owned(format!(
            "{command}\nif ($?) {{ exit 0 }} elseif ($LASTEXITCODE) {{ exit $LASTEXITCODE }} else {{ exit 1 }}"
        )),
    }
}

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
    fn linux_command_is_passed_through_without_a_wrapper() {
        let command = "printf '%s\\n' '$?'; exit 3 # keep this comment";
        let prepared = command_for_guest(crate::GuestOs::Linux, command);
        assert!(matches!(prepared, Cow::Borrowed(_)));
        assert_eq!(prepared, command);
    }

    /// Exercise the actual PowerShell `-Command` exit behavior without a VM. This
    /// runs on a Linux host with PowerShell installed, using /bin/sh as the native
    /// program. Windows' full 32-bit exit codes remain covered by windows_exec.
    #[test]
    fn windows_command_preserves_exit_codes_in_a_real_powershell() {
        let Some(powershell) = std::env::var_os("QLEAN_WINDOWS_EXEC_TEST_SHELL").or_else(|| {
            std::process::Command::new("pwsh")
                .arg("-NoLogo")
                .output()
                .ok()
                .map(|_| std::ffi::OsString::from("pwsh"))
        }) else {
            eprintln!("host PowerShell is absent; the Windows guest smoke covers this behavior");
            return;
        };
        let run = |command: &str| {
            std::process::Command::new(&powershell)
                .args(["-NoProfile", "-NonInteractive", "-Command", command])
                .output()
                .expect("run host PowerShell")
        };

        // Demonstrate the defect with the same native command used below.
        assert_eq!(run("/bin/sh -c 'exit 3'").status.code(), Some(1));
        for (command, code) in [
            ("/bin/sh -c 'exit 0'", 0),
            ("/bin/sh -c 'exit 1'", 1),
            ("/bin/sh -c 'exit 3'", 3),
            ("/bin/sh -c 'exit 255' # trailing comment", 255),
            ("exit 7", 7),
            ("Write-Error 'failure'", 1),
            ("throw 'failure'", 1),
            ("/bin/sh -c 'exit 3'; Write-Output 'recovered'", 0),
            ("/bin/sh -c 'exit 3'; Write-Error 'failure'", 3),
            ("Write-Output 'a b  c $literal ` ü 报告'", 0),
        ] {
            let prepared = command_for_guest(crate::GuestOs::Windows, command);
            let output = run(&prepared);
            assert_eq!(output.status.code(), Some(code), "{command}: {output:?}");
        }

        let output = run(&command_for_guest(
            crate::GuestOs::Windows,
            "Write-Output 'a b  c $literal ` ü 报告'; [Console]::Error.WriteLine('err') # comment",
        ));
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout).unwrap().trim(),
            "a b  c $literal ` ü 报告"
        );
        assert_eq!(String::from_utf8(output.stderr).unwrap().trim(), "err");
    }

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
        for code in [2u32, 3, 127, 128, 254, MAX_EXIT_CODE] {
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
