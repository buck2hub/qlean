use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use qapi::qmp::{RunState, query_status, system_powerdown};
use tracing::debug;

use crate::utils::QleanDirs;

/// How long a QMP exchange may take before it is abandoned.
///
/// QMP runs on QEMU's main loop, which a wedged guest can block. Without a budget the
/// `system_powerdown` request during shutdown would wait forever: teardown would never reach
/// its SIGKILL fallback and a caller (a test) would hang instead of failing. Abandoning the
/// request is safe — the caller already handles a powerdown that was not accepted by killing
/// QEMU — so this converts a hang into a warning.
const QMP_TIMEOUT: Duration = Duration::from_secs(10);

async fn with_qmp_client<T, F, Fut>(socket_path: &Path, f: F) -> Result<T>
where
    F: FnOnce(
        qapi::futures::QapiService<
            qapi::futures::QmpStreamTokio<tokio::io::WriteHalf<tokio::net::UnixStream>>,
        >,
    ) -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    with_qmp_client_within(socket_path, QMP_TIMEOUT, f).await
}

/// [`with_qmp_client`] with an explicit budget, so the timeout is testable in milliseconds.
async fn with_qmp_client_within<T, F, Fut>(socket_path: &Path, budget: Duration, f: F) -> Result<T>
where
    F: FnOnce(
        qapi::futures::QapiService<
            qapi::futures::QmpStreamTokio<tokio::io::WriteHalf<tokio::net::UnixStream>>,
        >,
    ) -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    tokio::time::timeout(budget, with_qmp_client_unbounded(socket_path, f))
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "QMP did not answer within {}s on {}; QEMU may be wedged, so the request was \
                 abandoned and teardown will kill it instead",
                budget.as_secs_f32(),
                socket_path.display()
            )
        })?
}

async fn with_qmp_client_unbounded<T, F, Fut>(socket_path: &Path, f: F) -> Result<T>
where
    F: FnOnce(
        qapi::futures::QapiService<
            qapi::futures::QmpStreamTokio<tokio::io::WriteHalf<tokio::net::UnixStream>>,
        >,
    ) -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let negotiation = qapi::futures::QmpStreamTokio::open_uds(socket_path)
        .await
        .with_context(|| {
            format!(
                "failed to connect to QMP socket at {}",
                socket_path.display()
            )
        })?;

    let stream = negotiation
        .negotiate()
        .await
        .context("QMP capability negotiation failed")?;

    let (service, handle) = stream.spawn_tokio();
    let result = f(service).await;
    drop(handle);
    result
}

/// Path to the QEMU QMP Unix socket for a VM run directory.
pub(crate) fn qmp_socket_path(vmid: &str) -> Result<PathBuf> {
    let dirs = QleanDirs::new()?;
    Ok(dirs.runs.join(vmid).join("qmp.sock"))
}

/// Whether a `query-status` answer still describes a machine that owns its disk.
///
/// `query-status` reports two different things: `running`, which is the guest CPU flag, and
/// `status`, the run state. The CPU flag is `false` for a paused guest, and also for a guest
/// whose run state is `io-error`, `internal-error`, `guest-panicked` or `watchdog` — the
/// states a failing host reaches (a full disk, a failed write) — while the QEMU process is
/// alive, holds the overlay open and is the only owner of that run directory.
///
/// Qlean asks one question: may a second QEMU be started on this disk, and is there anything
/// to shut down? Only `shutdown` answers "no": QEMU is on its way out. Every other state
/// answers "yes, this machine is still here", including the ones where the guest stopped.
fn a_live_machine_owns_its_disk(status: RunState) -> bool {
    !matches!(status, RunState::shutdown)
}

/// Query whether the VM's run directory is still owned by a live QEMU.
///
/// An answered QMP session is proof of the process; [`a_live_machine_owns_its_disk`] says
/// what its run state means. A stale socket with no QEMU behind it fails the connection
/// instead of answering, which is what makes "socket is there" different from "VM is alive".
pub(crate) async fn query_running(socket_path: &Path) -> Result<bool> {
    with_qmp_client(socket_path, |service| async move {
        let status = service
            .execute(query_status {})
            .await
            .context("query-status failed")?;
        debug!(
            "QMP query-status at {}: running={} status={:?}",
            socket_path.display(),
            status.running,
            status.status
        );
        Ok(a_live_machine_owns_its_disk(status.status))
    })
    .await
}

/// Request guest ACPI shutdown via QMP `system_powerdown`.
pub(crate) async fn powerdown(socket_path: &Path) -> Result<()> {
    with_qmp_client(socket_path, |service| async move {
        service
            .execute(system_powerdown {})
            .await
            .context("system-powerdown failed")?;
        debug!("QMP system-powerdown accepted at {}", socket_path.display());
        Ok(())
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bind a unix socket that accepts connections and never says anything.
    fn silent_socket(path: &Path) -> tokio::task::JoinHandle<()> {
        let listener = tokio::net::UnixListener::bind(path).expect("bind a silent QMP socket");
        tokio::spawn(async move {
            // Accept forever and hold the connection open without sending the QMP greeting.
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        })
    }

    #[tokio::test]
    async fn a_wedged_qmp_socket_is_abandoned_instead_of_hanging_teardown() {
        let dir = std::env::temp_dir().join(format!("qlean-qmp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create the tmp dir");
        let socket = dir.join("silent.sock");
        let _ = std::fs::remove_file(&socket);
        let server = silent_socket(&socket);

        let started = std::time::Instant::now();
        let error =
            with_qmp_client_within(&socket, Duration::from_millis(200), |service| async move {
                service
                    .execute(query_status {})
                    .await
                    .context("query-status failed")
            })
            .await
            .expect_err("a silent QMP socket must not be waited for forever");
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_secs(2),
            "the budget must end the wait, took {elapsed:?}"
        );
        let message = error.to_string();
        assert!(message.contains("did not answer"), "{message}");
        assert!(message.contains("silent.sock"), "{message}");
        assert!(message.contains("kill it instead"), "{message}");

        server.abort();
        let _ = std::fs::remove_file(&socket);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The run state, not the guest CPU flag, is what says whether the disk is still owned.
    #[test]
    fn a_guest_that_stopped_still_owns_its_disk() {
        for status in [
            RunState::running,
            RunState::paused,
            RunState::io_error,
            RunState::internal_error,
            RunState::guest_panicked,
            RunState::watchdog,
            RunState::prelaunch,
            RunState::suspended,
        ] {
            assert!(
                a_live_machine_owns_its_disk(status),
                "{status:?} is a live QEMU that still holds the overlay open"
            );
        }
        // QEMU is leaving: nothing to shut down, and a relaunch is safe once the process is
        // gone (which the pid check answers separately).
        assert!(!a_live_machine_owns_its_disk(RunState::shutdown));
    }

    /// Speak raw QMP so the test can send `stop` and read the reply the run state comes from.
    async fn raw_qmp(socket: &Path, commands: &[&str]) -> Vec<String> {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let stream = tokio::net::UnixStream::connect(socket)
            .await
            .expect("connect to the QMP socket");
        let (read_half, mut write_half) = stream.into_split();
        let mut lines = BufReader::new(read_half).lines();
        let greeting = lines
            .next_line()
            .await
            .expect("read the QMP greeting")
            .expect("the QMP greeting must be a line");
        let mut replies = vec![greeting];
        for command in commands {
            write_half
                .write_all(format!("{command}\n").as_bytes())
                .await
                .expect("send a QMP command");
            loop {
                let line = lines
                    .next_line()
                    .await
                    .expect("read a QMP reply")
                    .expect("a QMP reply must be a line");
                let is_event = line.contains("\"event\"");
                replies.push(line);
                if !is_event {
                    break;
                }
            }
        }
        replies
    }

    /// A paused guest is still a live QEMU holding the overlay: `is_running` must not answer
    /// "not running" for it, or `init_all`/`spawn_all` start a second QEMU on the same disk
    /// and `shutdown_all` skips the one that is still there.
    ///
    /// ```text
    /// cargo test --lib -- --ignored a_paused_vm_still_owns_its_disk
    /// ```
    #[tokio::test]
    #[ignore = "needs a real qemu-system-x86_64; run with --ignored on a host that has it"]
    async fn a_paused_vm_still_owns_its_disk() {
        let qemu = crate::qemu::qemu_system_program(crate::GuestArch::Amd64);
        if !tokio::process::Command::new(qemu)
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await
            .map(|status| status.success())
            .unwrap_or(false)
        {
            panic!("SMOKE-UNAVAILABLE: `{qemu}` is not runnable, the pause case was not exercised");
        }

        let dir = tempfile::tempdir().expect("temp dir");
        let socket = dir.path().join("qmp.sock");
        let mut child = tokio::process::Command::new(qemu)
            .args([
                "-m",
                "512",
                "-display",
                "none",
                "-nodefaults",
                "-qmp",
                &format!("unix:{},server=on,wait=off", socket.display()),
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn qemu");

        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        let mut live = false;
        while std::time::Instant::now() < deadline {
            if query_running(&socket).await.is_ok_and(|running| running) {
                live = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(live, "the VM never reported itself as live");

        let replies = raw_qmp(
            &socket,
            &[
                "{\"execute\":\"qmp_capabilities\"}",
                "{\"execute\":\"stop\"}",
            ],
        )
        .await;
        let status = raw_qmp(
            &socket,
            &[
                "{\"execute\":\"qmp_capabilities\"}",
                "{\"execute\":\"query-status\"}",
            ],
        )
        .await;
        let answer = status.last().expect("a query-status reply");
        println!("raw query-status after stop: {answer}");
        let compact: String = answer.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(
            compact.contains("\"status\":\"paused\"") && compact.contains("\"running\":false"),
            "the guest CPU flag must be false while paused, or this test proves nothing: {answer}"
        );
        assert!(
            replies.iter().any(|reply| reply.contains("return")),
            "stop must be accepted: {replies:?}"
        );
        assert!(
            child.try_wait().expect("qemu state").is_none(),
            "the QEMU process must still be alive while the guest is paused"
        );
        assert!(
            query_running(&socket)
                .await
                .expect("QMP answers for a paused VM"),
            "a paused VM still owns its run directory; reporting 'not running' lets a second \
             QEMU be started on the same overlay"
        );

        let _ = child.start_kill();
        let _ = child.wait().await;
    }

    #[tokio::test]
    async fn a_missing_qmp_socket_reports_its_path() {
        let error = query_running(Path::new("/nonexistent/qlean/qmp.sock"))
            .await
            .expect_err("a missing socket is an error, not a running VM");
        let message = format!("{error:#}");
        assert!(message.contains("/nonexistent/qlean/qmp.sock"), "{message}");
    }
}
