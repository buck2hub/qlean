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

/// Query whether the VM is running according to QMP `query-status`.
pub(crate) async fn query_running(socket_path: &Path) -> Result<bool> {
    with_qmp_client(socket_path, |service| async move {
        let status = service
            .execute(query_status {})
            .await
            .context("query-status failed")?;
        Ok(status.running && matches!(status.status, RunState::running))
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

    #[tokio::test]
    async fn a_missing_qmp_socket_reports_its_path() {
        let error = query_running(Path::new("/nonexistent/qlean/qmp.sock"))
            .await
            .expect_err("a missing socket is an error, not a running VM");
        let message = format!("{error:#}");
        assert!(message.contains("/nonexistent/qlean/qmp.sock"), "{message}");
    }
}
