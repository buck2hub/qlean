//! OrbStack host gate for macOS.
//!
//! Command spelling lives here. Unit tests inject the lookup and the status
//! text, so they never spawn `orb`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Result, bail};

use crate::utils::{bounded_output, is_executable_file};

/// How long `orb status` may take before the probe gives up.
const STATUS_BUDGET: Duration = Duration::from_secs(5);

/// Text returned when the `orb` binary is not on `PATH`.
pub(crate) fn missing_orbstack_message() -> &'static str {
    "Qlean on macOS needs OrbStack. Install it with `brew install orbstack`, start OrbStack, and retry. Installing QEMU on the Mac is not the fix."
}

/// Where `orb` was found, if anywhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OrbLocation {
    /// No file named `orb` on `PATH`.
    Missing,
    /// A file named `orb` exists, but the host cannot execute it.
    NotExecutable { path: PathBuf },
    /// An executable `orb` is on `PATH`.
    Found { path: PathBuf },
}

/// Decide whether OrbStack can be used, from an injected lookup and status.
///
/// `status` is the stdout of `orb status`, or the error string when that
/// command could not be run. It is ignored unless `location` is [`OrbLocation::Found`].
pub(crate) fn classify_orb(location: &OrbLocation, status: Result<&str, &str>) -> Result<()> {
    match location {
        OrbLocation::Missing => bail!("{}", missing_orbstack_message()),
        OrbLocation::NotExecutable { path } => bail!(
            "OrbStack's `orb` is at {} but cannot be executed. Fix the file mode or remount that filesystem without `noexec`, then retry.",
            path.display()
        ),
        OrbLocation::Found { .. } => match status {
            Ok(text) if text.trim() == "Running" => Ok(()),
            Ok(text) => {
                let summary = one_line(text);
                bail!(
                    "OrbStack is installed but not running. Start OrbStack (`orb`, or `orb start` if the app is stopped). `orb status` should print `Running`. The probe returned: {summary}"
                )
            }
            Err(error) => {
                let summary = one_line(error);
                bail!(
                    "OrbStack is installed but not running. Start OrbStack (`orb`, or `orb start` if the app is stopped). `orb status` should print `Running`. The probe failed: {summary}"
                )
            }
        },
    }
}

/// Look up `orb` on `PATH` and ask `orb status`, with a timeout.
pub(crate) async fn ensure_orbstack() -> Result<()> {
    let location = locate_orb();
    let status = match &location {
        OrbLocation::Found { path } => run_status(path).await,
        _ => Err(String::new()),
    };
    let status_ref = match &status {
        Ok(text) => Ok(text.as_str()),
        Err(error) => Err(error.as_str()),
    };
    classify_orb(&location, status_ref)
}

fn one_line(text: &str) -> String {
    let mut line = text.split_whitespace().collect::<Vec<_>>().join(" ");
    const LIMIT: usize = 120;
    if line.len() > LIMIT {
        line.truncate(LIMIT);
        line.push('…');
    }
    if line.is_empty() {
        "(empty)".to_string()
    } else {
        line
    }
}

fn locate_orb() -> OrbLocation {
    let Some(paths) = std::env::var_os("PATH") else {
        return OrbLocation::Missing;
    };
    let mut unusable: Option<PathBuf> = None;
    for dir in std::env::split_paths(&paths) {
        let candidate = dir.join("orb");
        if is_executable_file(&candidate) {
            return OrbLocation::Found { path: candidate };
        }
        if unusable.is_none() && candidate.is_file() {
            unusable = Some(candidate);
        }
    }
    match unusable {
        Some(path) => OrbLocation::NotExecutable { path },
        None => OrbLocation::Missing,
    }
}

async fn run_status(program: &Path) -> Result<String, String> {
    let mut command = tokio::process::Command::new(program);
    command.arg("status");
    match bounded_output(command, STATUS_BUDGET, "ask OrbStack whether it is running").await {
        Ok(output) if output.status.success() => {
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        }
        Ok(output) => Err(format!(
            "exit {}: {}",
            output.status,
            one_line(&String::from_utf8_lossy(&output.stderr))
        )),
        Err(error) => Err(format!("{error:#}")),
    }
}

#[cfg(test)]
mod orbstack_prerequisite {
    use super::{OrbLocation, classify_orb, missing_orbstack_message};

    fn assert_no_qemu_install(message: &str) {
        let lower = message.to_ascii_lowercase();
        assert!(
            !lower.contains("install qemu") && !lower.contains("brew install qemu"),
            "{message}"
        );
    }

    #[test]
    fn a_missing_binary_names_orbstack_and_brew() {
        let error = classify_orb(&OrbLocation::Missing, Ok("Running")).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("OrbStack"), "{message}");
        assert!(message.contains("brew install orbstack"), "{message}");
        assert_eq!(missing_orbstack_message(), message);
        assert_no_qemu_install(&message);
    }

    #[test]
    fn an_unexecutable_binary_names_the_path_and_noexec() {
        let error = classify_orb(
            &OrbLocation::NotExecutable {
                path: "/usr/local/bin/orb".into(),
            },
            Ok("Running"),
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("/usr/local/bin/orb"), "{message}");
        assert!(message.contains("noexec"), "{message}");
        assert!(message.contains("OrbStack"), "{message}");
        assert_no_qemu_install(&message);
    }

    #[test]
    fn a_stopped_runtime_is_not_the_install_error() {
        let error = classify_orb(
            &OrbLocation::Found {
                path: "/usr/local/bin/orb".into(),
            },
            Ok("Stopped"),
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("not running"), "{message}");
        assert!(message.contains("orb start"), "{message}");
        assert!(!message.contains("brew install orbstack"), "{message}");
        assert_no_qemu_install(&message);
    }

    #[test]
    fn a_failed_status_probe_is_its_own_error() {
        let error = classify_orb(
            &OrbLocation::Found {
                path: "/usr/local/bin/orb".into(),
            },
            Err("timed out"),
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("not running"), "{message}");
        assert!(message.contains("timed out"), "{message}");
        assert_no_qemu_install(&message);
    }

    #[test]
    fn a_running_status_is_ready_and_creates_nothing() {
        classify_orb(
            &OrbLocation::Found {
                path: "/usr/local/bin/orb".into(),
            },
            Ok("Running\n"),
        )
        .expect("Running is the ready status");
    }
}
