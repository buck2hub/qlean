//! Windows first-boot deployment contract (ADR-WIN-03).
//!
//! Qlean never regenerates an installed Windows image. Instead every Windows VM
//! boots a pre-generalized image (`sysprep /generalize /oobe /shutdown`) that ships a
//! first-boot scheduled task, and Qlean attaches a small ISO9660 *seed* medium that
//! is readable only to that task:
//!
//! | File on the seed medium | Purpose |
//! |---|---|
//! | `qlean/authorized_keys` | Client public key for the `qlean` account (and for `administrators_authorized_keys` when that account is an administrator) |
//! | `qlean/ssh_host_ed25519_key` | Per-VM SSH host private key, randomly generated on the host |
//! | `qlean/deploy.json` | Contract version, account name and marker path |
//!
//! The seed medium contains no client private key and no reusable password: the image
//! ships with password authentication disabled, and the first-boot task installs the
//! authorized keys with an owner-only ACL, pins the host key, starts `sshd`, then writes
//! [`GUEST_DEPLOY_MARKER`]. Once the marker is observed, [`DeploySeed::remove`] deletes
//! both the staged directory and the ISO, so later boots never see the seed again.
//!
//! The contract is documented for image authors in README "Windows image contract".

use std::{
    fmt,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::{
    MachineConfig,
    ssh::{PersistedSshKeypair, generate_keypair},
};

/// ISO9660 volume label of the Windows seed medium.
pub(crate) const SEED_VOLUME_LABEL: &str = "QLEANSEED";

/// Ready-to-use directory on the seed medium. The whole seed lives under this
/// path so the guest task only has to read one directory.
pub(crate) const SEED_ROOT: &str = "qlean";

/// Account Qlean provisions on Windows guests (single source of truth for the
/// transport layer, so it is not repeated in the SSH client).
pub(crate) const GUEST_USERNAME: &str = "qlean";

/// Marker file written by the image's first-boot task once the deployment is done.
pub(crate) const GUEST_DEPLOY_MARKER: &str = r"C:\ProgramData\qlean\deployed";

/// Default budget for the first-boot deployment.
///
/// This is deliberately independent of the Linux SSH connect budget (180s on KVM,
/// 300s on TCG): a Windows first boot runs `sysprep` specialize/OOBE work, installs
/// keys, restarts `sshd` and may need several reboots before it is reachable.
/// `SPK-02` could not be executed in the current environment, so this value is the
/// documented expectation for a cold first boot and must be re-measured on a real
/// Windows KVM host; `MachineConfig::ssh_timeout` overrides it.
pub(crate) const DEPLOY_TIMEOUT_SECS: u64 = 900;

/// How often the guest is probed for the deploy marker while waiting.
pub(crate) const DEPLOY_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Contract written to `qlean/deploy.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct DeployContract {
    /// Contract version; bumped when the file layout changes incompatibly.
    pub version: u32,
    /// Account that receives the authorized key.
    pub username: String,
    /// Path the guest task writes once the deployment succeeded.
    pub marker: String,
}

impl DeployContract {
    pub(crate) fn current() -> Self {
        Self {
            version: 1,
            username: GUEST_USERNAME.to_string(),
            marker: GUEST_DEPLOY_MARKER.to_string(),
        }
    }
}

/// A staged Windows seed medium.
///
/// Holds only paths: the host key material is written to disk and never kept in
/// memory, and the `Debug` implementation of this type therefore cannot leak it.
pub(crate) struct DeploySeed {
    dir: PathBuf,
    iso: PathBuf,
}

impl fmt::Debug for DeploySeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeploySeed")
            .field("dir", &self.dir)
            .field("iso", &self.iso)
            .finish_non_exhaustive()
    }
}

impl DeploySeed {
    /// Stage the seed files under `run_dir/seed` without building the ISO.
    ///
    /// `client_pubkey` is the client's public key only; the client private key
    /// never leaves the host secrets directory.
    pub(crate) async fn stage(
        run_dir: &Path,
        client_pubkey: &str,
        host_key: &PersistedSshKeypair,
    ) -> Result<Self> {
        let dir = run_dir.join("seed");
        let root = dir.join(SEED_ROOT);
        tokio::fs::create_dir_all(&root).await.with_context(|| {
            format!("failed to create Windows seed directory {}", root.display())
        })?;

        let authorized_keys = ensure_trailing_newline(client_pubkey);
        let authorized_keys_path = root.join("authorized_keys");
        tokio::fs::write(&authorized_keys_path, authorized_keys)
            .await
            .with_context(|| {
                format!(
                    "failed to write Windows seed authorized_keys at {}",
                    authorized_keys_path.display()
                )
            })?;
        set_owner_only(&authorized_keys_path).await?;

        let contract = serde_json::to_vec_pretty(&DeployContract::current())?;
        let contract_path = root.join("deploy.json");
        tokio::fs::write(&contract_path, contract)
            .await
            .with_context(|| {
                format!(
                    "failed to write Windows seed contract at {}",
                    contract_path.display()
                )
            })?;

        let host_key_path = root.join("ssh_host_ed25519_key");
        tokio::fs::write(&host_key_path, &host_key.privkey_str)
            .await
            .with_context(|| {
                format!(
                    "failed to write Windows seed host key at {}",
                    host_key_path.display()
                )
            })?;
        set_owner_only(&host_key_path).await?;

        debug!(
            "Staged Windows seed medium in {} (authorized_keys, deploy.json, ssh_host_ed25519_key)",
            root.display()
        );

        Ok(Self {
            dir,
            iso: run_dir.join("seed.iso"),
        })
    }

    /// Path of the seed ISO that QEMU attaches on first boot.
    pub(crate) fn iso_path(&self) -> &Path {
        &self.iso
    }

    /// Build the ISO9660+Joliet image from the staged directory.
    ///
    /// The seed root is grafted as `qlean/` so the guest sees `D:\qlean\...`
    /// regardless of how the medium is mounted.
    pub(crate) async fn build(&self) -> Result<()> {
        let mut cmd = tokio::process::Command::new("xorriso");
        cmd.args(["-as", "mkisofs"])
            .args(["-V", SEED_VOLUME_LABEL])
            .args(["-J", "-R"])
            .args(["-o"])
            .arg(&self.iso)
            .arg("-graft-points")
            .arg(format!(
                "{SEED_ROOT}={}",
                self.dir.join(SEED_ROOT).display()
            ));
        debug!("Creating Windows seed ISO with command:\n{:?}", cmd);

        let output = cmd.output().await.with_context(|| {
            "failed to run `xorriso` to build the Windows seed ISO; install the `xorriso` package"
        })?;
        if !output.status.success() {
            bail!(
                "failed to build the Windows seed ISO: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(())
    }

    /// Remove the staged directory and the ISO after a successful deployment.
    ///
    /// Failing to clean up is not fatal: the seed holds only a public key, a
    /// per-VM host key and the contract, and it is never attached again. The
    /// error is returned so callers can log it.
    pub(crate) async fn remove(self) -> Result<()> {
        let mut first_error: Option<anyhow::Error> = None;
        for path in [&self.iso, &self.dir] {
            let result = if path == &self.dir {
                tokio::fs::remove_dir_all(path).await
            } else {
                match tokio::fs::remove_file(path).await {
                    Ok(()) => Ok(()),
                    // Already gone is success for an idempotent cleanup.
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    Err(e) => Err(e),
                }
            };
            if let Err(e) = result
                && first_error.is_none()
            {
                first_error = Some(e.into());
            }
        }
        match first_error {
            Some(e) => Err(e.context("failed to clean up the Windows seed medium")),
            None => Ok(()),
        }
    }
}

/// Generate the per-VM SSH host keypair.
///
/// The keypair lives in the run directory: the private half is injected into the
/// seed medium, while the public half stays on the host for host-key pinning.
pub(crate) fn generate_host_key(run_dir: &Path) -> Result<PersistedSshKeypair> {
    generate_keypair(&run_dir.join("ssh_host_ed25519_key")).with_context(|| {
        format!(
            "failed to generate the per-VM SSH host key in {}",
            run_dir.display()
        )
    })
}

/// Budget for the first-boot deployment wait.
///
/// `MachineConfig::ssh_timeout` overrides the Windows default; an unset timeout
/// uses [`DEPLOY_TIMEOUT_SECS`] rather than the Linux connect budget.
pub(crate) fn deploy_timeout(config: &MachineConfig) -> Duration {
    config
        .ssh_timeout
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(DEPLOY_TIMEOUT_SECS))
}

/// Actionable message for a deployment that exceeded its budget.
pub(crate) fn deploy_timeout_message(timeout: Duration) -> String {
    format!(
        "Windows guest did not finish its first-boot deployment within {}s.\n\
         The image is expected to run Qlean's first-boot task, which installs the \
         authorized key from the `{SEED_VOLUME_LABEL}` medium, enables `sshd` without \
         password authentication, and writes `{GUEST_DEPLOY_MARKER}`.\n\
         Check that the image follows the README \"Windows image contract\", that the \
         `{GUEST_USERNAME}` account exists, and that the guest can reach the seed \
         medium. The seed medium is kept under the run directory until deployment \
         succeeds.",
        timeout.as_secs()
    )
}

fn ensure_trailing_newline(content: &str) -> String {
    let trimmed = content.trim();
    format!("{trimmed}\n")
}

async fn set_owner_only(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .await
            .with_context(|| format!("failed to restrict permissions on {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT_PUBKEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICLIENTPUBKEYCLIENTPUBKEYCLIENTPUBKEY qlean-test";

    async fn stage(run_dir: &Path) -> Result<(DeploySeed, PersistedSshKeypair)> {
        let host_key = generate_host_key(run_dir)?;
        let seed = DeploySeed::stage(run_dir, CLIENT_PUBKEY, &host_key).await?;
        Ok((seed, host_key))
    }

    fn read(path: &Path) -> String {
        std::fs::read_to_string(path).expect("seed file is readable")
    }

    #[tokio::test]
    async fn test_windows_deploy_seed_contract_files() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let (seed, host_key) = stage(tmp.path()).await?;
        let root = tmp.path().join("seed").join(SEED_ROOT);

        let authorized_keys = read(&root.join("authorized_keys"));
        assert_eq!(authorized_keys, format!("{CLIENT_PUBKEY}\n"));
        // The client private key must never be part of the seed.
        assert!(!authorized_keys.contains("PRIVATE KEY"));

        let host_key_on_seed = read(&root.join("ssh_host_ed25519_key"));
        assert_eq!(host_key_on_seed, host_key.privkey_str);
        assert!(host_key_on_seed.contains("PRIVATE KEY"));

        let contract: DeployContract = serde_json::from_str(&read(&root.join("deploy.json")))?;
        assert_eq!(contract, DeployContract::current());
        assert_eq!(contract.username, GUEST_USERNAME);
        assert_eq!(contract.marker, GUEST_DEPLOY_MARKER);

        assert_eq!(seed.iso_path(), tmp.path().join("seed.iso"));
        Ok(())
    }

    #[tokio::test]
    async fn test_windows_deploy_seed_files_are_owner_only() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir()?;
        let (_seed, _host_key) = stage(tmp.path()).await?;
        let root = tmp.path().join("seed").join(SEED_ROOT);
        for name in ["authorized_keys", "ssh_host_ed25519_key"] {
            let mode = std::fs::metadata(root.join(name))?.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{name} should be 0600, got {mode:o}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_windows_deploy_host_key_is_per_vm() -> Result<()> {
        let first = tempfile::tempdir()?;
        let second = tempfile::tempdir()?;
        let (_, first_key) = stage(first.path()).await?;
        let (_, second_key) = stage(second.path()).await?;
        assert_ne!(first_key.pubkey_str, second_key.pubkey_str);
        assert_ne!(first_key.privkey_str, second_key.privkey_str);
        Ok(())
    }

    #[tokio::test]
    async fn test_windows_deploy_seed_debug_does_not_leak_key_material() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let (seed, host_key) = stage(tmp.path()).await?;
        let debug = format!("{seed:?}");
        assert!(debug.contains("DeploySeed"));
        assert!(!debug.contains("PRIVATE KEY"));
        assert!(!debug.contains(host_key.privkey_str.trim()));
        Ok(())
    }

    #[tokio::test]
    async fn test_windows_deploy_seed_cleanup_removes_media() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let (seed, _host_key) = stage(tmp.path()).await?;
        let dir = tmp.path().join("seed");
        std::fs::write(seed.iso_path(), b"fake iso")?;
        assert!(dir.exists());

        seed.remove().await?;
        assert!(!dir.exists());
        assert!(!tmp.path().join("seed.iso").exists());
        Ok(())
    }

    #[test]
    fn test_windows_deploy_timeout_defaults() {
        let default = deploy_timeout(&MachineConfig::default());
        assert_eq!(default, Duration::from_secs(DEPLOY_TIMEOUT_SECS));
        // The Windows deployment budget is independent of the Linux connect budget.
        assert_ne!(default, Duration::from_secs(180));
        assert_ne!(default, Duration::from_secs(300));

        let overridden = MachineConfig {
            ssh_timeout: Some(45),
            ..MachineConfig::default()
        };
        assert_eq!(deploy_timeout(&overridden), Duration::from_secs(45));
    }

    #[test]
    fn test_windows_deploy_timeout_error_is_actionable() {
        let message = deploy_timeout_message(Duration::from_secs(DEPLOY_TIMEOUT_SECS));
        assert!(message.contains("first-boot deployment"), "{message}");
        assert!(message.contains(GUEST_DEPLOY_MARKER), "{message}");
        assert!(message.contains("README"), "{message}");
        assert!(message.contains(SEED_VOLUME_LABEL), "{message}");
        assert!(message.contains("seed medium is kept"), "{message}");
        assert!(!message.contains("PRIVATE KEY"));
    }
}
