use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use qapi::qmp::{RunState, query_status, system_powerdown};
use tracing::debug;

use crate::utils::QleanDirs;

async fn with_qmp_client<T, F, Fut>(socket_path: &Path, f: F) -> Result<T>
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
