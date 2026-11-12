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

/// TCP port Windows guests expose their OpenSSH server on.
pub(crate) const SSH_PORT: u16 = 22;

/// Command used as the Windows readiness probe once the session is up.
///
/// `cmd /c ver` exercises the transport, the deployed key and a working
/// non-interactive command channel without depending on PowerShell semantics
/// (those arrive with the `exec` shell abstraction).
pub(crate) const READINESS_COMMAND: &str = "cmd /c ver";

/// PowerShell query returning `<mac> <address>` pairs for the guest's adapters.
///
/// Only IPv4 addresses of adapters that are actually up are reported, and loopback and
/// APIPA (`169.254.0.0/16`) addresses are excluded so a link-local address cannot be
/// mistaken for the leased one.
pub(crate) const GUEST_IP_QUERY: &str = "%ErrorActionPreference='Stop'; Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object { $mac = $_.MacAddress; Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } | ForEach-Object { '{0} {1}' -f $mac, $_.IPAddress } }";

/// Normalize a MAC address for comparison (`-`, `:` and case are not significant).
pub(crate) fn normalize_mac(mac: &str) -> String {
    mac.chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_ascii_lowercase()
}

/// Parse `<mac> <address>` lines reported by [`GUEST_IP_QUERY`].
///
/// Unparseable lines are skipped instead of failing the whole query: PowerShell may
/// emit warnings or blank lines alongside the pairs.
pub(crate) fn parse_adapter_addresses(output: &str) -> Vec<(String, std::net::IpAddr)> {
    output
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let mac = parts.next()?;
            let addr = parts.next()?;
            let ip = addr.parse::<std::net::IpAddr>().ok()?;
            // Only IPv4 is usable for the transport: a link-local IPv6 address has no
            // scope id here, exactly as the DHCP lease path already assumes.
            ip.is_ipv4().then(|| (normalize_mac(mac), ip))
        })
        .collect()
}

/// Pick the address that belongs to `mac`, refusing to guess.
///
/// Qlean assigns one MAC per VM, so a Windows guest must report exactly one IPv4 address
/// for its own MAC. Zero matches means the guest has no usable IPv4 address; more than one is
/// ambiguous (multiple NICs, or a stale address). Neither case may silently fall back to
/// another VM's lease.
pub(crate) fn select_guest_address(
    addresses: &[(String, std::net::IpAddr)],
    mac: &str,
) -> Result<std::net::IpAddr> {
    let expected = normalize_mac(mac);
    // Decide on IPv4 only. Keeping the filter here as well as in the parser means a
    // reported IPv6 address can neither be dialled nor make a single IPv4 address look
    // ambiguous.
    let mut matches = addresses
        .iter()
        .filter(|(reported_mac, ip)| *reported_mac == expected && ip.is_ipv4())
        .map(|(_, ip)| *ip);

    let Some(first) = matches.next() else {
        let seen = addresses
            .iter()
            .map(|(reported_mac, ip)| format!("{reported_mac}={ip}"))
            .collect::<Vec<_>>();
        anyhow::bail!(
            "Windows guest did not report an IPv4 address for MAC {mac} (reported: {seen:?}).\n\
             Check that the guest brought up its virtio network adapter and received a lease."
        );
    };

    if matches.next().is_some() {
        let candidates = addresses
            .iter()
            .filter(|(reported_mac, ip)| *reported_mac == expected && ip.is_ipv4())
            .map(|(_, ip)| ip.to_string())
            .collect::<Vec<_>>();
        anyhow::bail!(
            "Windows guest reported several IPv4 addresses for MAC {mac} ({candidates:?}); \
             cannot decide which one is the leased address."
        );
    }

    Ok(first)
}

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
        // The seed holds the guest's SSH host private key until deployment finishes, so
        // neither the directory nor the medium itself may be readable by other users.
        crate::utils::restrict_dir(&dir)?;
        crate::utils::restrict_dir(&root)?;

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
            .arg(crate::utils::path_argument(
                &format!("{SEED_ROOT}="),
                &self.dir.join(SEED_ROOT),
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
        // `xorriso` creates the file with the process umask (typically world-readable),
        // and the medium carries the guest host private key: seal it before QEMU attaches it.
        seal_seed_medium(&self.iso).await?;
        Ok(())
    }

    /// Remove the staged directory and the ISO after a successful deployment.
    ///
    /// Failing to clean up is not fatal: the seed holds only a public key, a
    /// per-VM host key and the contract, and it is never attached again. The
    /// error is returned so callers can log it — [`Machine::confirm_deployment`]
    /// warns instead of failing a deployment that already succeeded.
    ///
    /// Both paths are removed even if one of them fails, and a path that is
    /// already gone is success: this runs after a guest-side reboot, so a
    /// previous attempt may have cleaned up one half already.
    pub(crate) async fn remove(self) -> Result<()> {
        let mut first_error: Option<anyhow::Error> = None;
        for path in [&self.iso, &self.dir] {
            let result = if path == &self.dir {
                tokio::fs::remove_dir_all(path).await
            } else {
                tokio::fs::remove_file(path).await
            };
            match result {
                Ok(()) => {}
                // Already gone is success for an idempotent cleanup.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) if first_error.is_none() => first_error = Some(e.into()),
                Err(_) => {}
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

/// Seal the built seed medium so only the owning user can read it.
///
/// Split out of [`DeploySeed::build`] because `build` needs `xorriso`: the permission
/// change is the part that must not regress, and it can be exercised on any file.
async fn seal_seed_medium(path: &Path) -> Result<()> {
    set_owner_only(path).await.with_context(|| {
        format!(
            "failed to restrict the Windows seed medium {} to 0600",
            path.display()
        )
    })
}

async fn set_owner_only(path: &Path) -> Result<()> {
    crate::utils::restrict_file(path)
}

/// Quote a path as a PowerShell single-quoted literal.
///
/// Single-quoted literals are the only PowerShell string form with no interpolation, so a
/// path containing `$`, backticks, spaces or non-ASCII stays exactly as written. A single
/// quote inside the value is doubled, which is how PowerShell escapes it.
pub(crate) fn powershell_literal(text: &str) -> String {
    format!("'{}'", text.replace('\'', "''"))
}

/// PowerShell command copying one file, for `Machine::copy`.
///
/// The guest's default shell is already PowerShell (see the README Windows image
/// contract), so the cmdlet runs as the command itself. It must *not* be wrapped in
/// `powershell -Command "..."`: the outer shell would parse that double-quoted string
/// and expand `$` in a path such as `C:/Program Files/a$b`, silently redirecting the
/// copy to a different file.
pub(crate) fn copy_file_command(from: &str, to: &str) -> String {
    format!(
        "Copy-Item -LiteralPath {} -Destination {} -Force",
        powershell_literal(from),
        powershell_literal(to)
    )
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
        // The directories must not be traversable either: the host private key and the
        // seed medium live inside them.
        for path in [tmp.path().join("seed"), root] {
            let mode = std::fs::metadata(&path)?.permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{path:?} should be 0700, got {mode:o}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_seed_medium_is_sealed_after_the_build() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir()?;
        let iso = tmp.path().join("seed.iso");
        // `xorriso` leaves the medium with the process umask.
        std::fs::write(&iso, b"seed")?;
        std::fs::set_permissions(&iso, std::fs::Permissions::from_mode(0o644))?;

        seal_seed_medium(&iso).await?;
        let mode = std::fs::metadata(&iso)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "seed medium should be 0600, got {mode:o}");
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
    async fn test_windows_deploy_seed_cleanup_is_idempotent() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let (seed, _host_key) = stage(tmp.path()).await?;
        std::fs::write(seed.iso_path(), b"fake iso")?;
        // Half of the cleanup already happened, for instance when the guest rebooted
        // between two attempts: that is not a failure.
        std::fs::remove_dir_all(tmp.path().join("seed"))?;

        seed.remove().await?;
        assert!(!tmp.path().join("seed.iso").exists());
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
    fn windows_ip_parses_adapter_pairs() {
        let output = "52-54-00-AA-BB-CC 192.168.221.42\r\n52-54-00-11-22-33 192.168.221.43\n";
        let addresses = parse_adapter_addresses(output);
        assert_eq!(addresses.len(), 2);
        assert_eq!(addresses[0].0, "525400aabbcc");
        assert_eq!(addresses[0].1.to_string(), "192.168.221.42");
        assert_eq!(addresses[1].0, "525400112233");
    }

    #[test]
    fn windows_ip_parser_skips_noise_and_unparseable_lines() {
        let output = "WARNING: something\n\nnot-an-address\n52:54:00:aa:bb:cc 192.168.221.42\n";
        let addresses = parse_adapter_addresses(output);
        assert_eq!(addresses.len(), 1);
        assert_eq!(addresses[0].0, "525400aabbcc");
        assert_eq!(addresses[0].1.to_string(), "192.168.221.42");
    }

    #[test]
    fn windows_ip_selects_only_the_matching_mac() {
        let output = "52-54-00-11-22-33 192.168.221.43\n52-54-00-AA-BB-CC 192.168.221.42\n";
        let addresses = parse_adapter_addresses(output);
        let selected = select_guest_address(&addresses, "52:54:00:aa:bb:cc").unwrap();
        assert_eq!(selected.to_string(), "192.168.221.42");
    }

    #[test]
    fn windows_ip_without_own_address_is_an_actionable_error() {
        // Only another VM's address was reported: never fall back to it.
        let output = "52-54-00-11-22-33 192.168.221.43\n";
        let addresses = parse_adapter_addresses(output);
        let err = select_guest_address(&addresses, "52:54:00:aa:bb:cc")
            .expect_err("another VM's address must not be reused")
            .to_string();
        assert!(err.contains("52:54:00:aa:bb:cc"), "{err}");
        assert!(err.contains("did not report an IPv4 address"), "{err}");
        // The leases that were seen are listed to make the failure debuggable, but they
        // are never returned as this VM's address.
        assert!(err.contains("525400112233=192.168.221.43"), "{err}");
        assert!(err.contains("virtio network adapter"), "{err}");
    }

    #[test]
    fn windows_ip_multiple_addresses_for_one_mac_are_ambiguous() {
        let output = "52-54-00-AA-BB-CC 192.168.221.42\n52-54-00-AA-BB-CC 169.254.10.20\n";
        let addresses = parse_adapter_addresses(output);
        let err = select_guest_address(&addresses, "52:54:00:aa:bb:cc")
            .expect_err("multiple addresses must not be resolved by guessing")
            .to_string();
        assert!(err.contains("several IPv4 addresses"), "{err}");
        assert!(err.contains("192.168.221.42"), "{err}");
        assert!(err.contains("169.254.10.20"), "{err}");
    }

    #[test]
    fn windows_ip_query_excludes_loopback_and_apipa() {
        // The PowerShell query itself must not offer loopback/link-local candidates.
        assert!(GUEST_IP_QUERY.contains("127.*"));
        assert!(GUEST_IP_QUERY.contains("169.254.*"));
        assert!(GUEST_IP_QUERY.contains("Get-NetIPAddress"));
        assert!(!GUEST_IP_QUERY.contains("hostname -I"));
    }

    #[test]
    fn windows_guest_address_ignores_ipv6_for_the_same_adapter() {
        // A dual-stack adapter reports both families; only IPv4 can be dialled, and the
        // IPv6 row must not make the answer look ambiguous.
        let output =
            "52-54-00-AA-BB-CC 192.168.221.42\n52-54-00-AA-BB-CC fe80::4c2f:1ff:fe12:3456\n";
        let addresses = parse_adapter_addresses(output);
        assert_eq!(addresses.len(), 1, "{addresses:?}");
        let selected = select_guest_address(&addresses, "52:54:00:aa:bb:cc").unwrap();
        assert_eq!(selected.to_string(), "192.168.221.42");
    }

    #[test]
    fn windows_guest_address_refuses_an_ipv6_only_report() {
        let output = "52-54-00-AA-BB-CC fe80::4c2f:1ff:fe12:3456\n";
        let addresses = parse_adapter_addresses(output);
        let err = select_guest_address(&addresses, "52:54:00:aa:bb:cc")
            .expect_err("an IPv6-only report must not be dialled")
            .to_string();
        assert!(err.contains("IPv4"), "{err}");
    }

    #[test]
    fn windows_guest_address_selection_filters_ipv6_even_if_a_caller_passes_it() {
        // Defence in depth: the selection site enforces IPv4 too, so a future query change
        // cannot smuggle an unusable address through.
        let addresses = vec![
            (
                normalize_mac("52-54-00-AA-BB-CC"),
                "fe80::1".parse::<std::net::IpAddr>().unwrap(),
            ),
            (
                normalize_mac("52-54-00-AA-BB-CC"),
                "192.168.221.43".parse::<std::net::IpAddr>().unwrap(),
            ),
        ];
        let selected = select_guest_address(&addresses, "52:54:00:aa:bb:cc").unwrap();
        assert_eq!(selected.to_string(), "192.168.221.43");
    }

    #[test]
    fn windows_copy_command_keeps_interpolation_sensitive_paths_literal() {
        let cmd = copy_file_command("C:/Program Files/a$b.txt", "C:/Users/qlean/target `x.txt");
        assert_eq!(
            cmd,
            "Copy-Item -LiteralPath 'C:/Program Files/a$b.txt' -Destination 'C:/Users/qlean/target `x.txt' -Force"
        );
        // No nested PowerShell invocation: the default shell already is PowerShell, and a
        // `powershell -Command "..."` wrapper would interpolate `$b` before the copy runs.
        assert!(!cmd.contains("-Command"), "{cmd}");
        assert!(!cmd.contains('"'), "{cmd}");
    }

    #[test]
    fn windows_powershell_literal_quotes_paths_without_interpolation() {
        // Machine::copy passes an already-normalized GuestPath.
        assert_eq!(powershell_literal("C:/Users/qlean"), "'C:/Users/qlean'");
        assert_eq!(
            powershell_literal("C:/Program Files/a$b"),
            "'C:/Program Files/a$b'"
        );
        assert_eq!(powershell_literal("C:/it's/a.txt"), "'C:/it''s/a.txt'");
        assert_eq!(
            powershell_literal("C:/döner 报告.txt"),
            "'C:/döner 报告.txt'"
        );
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
