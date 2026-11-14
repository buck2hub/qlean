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

/// Command that reports whether the deployment marker exists.
///
/// The marker path is quoted: `cmd` splits an unquoted path on spaces, so a future marker
/// location (or a `%ProgramData%` rendered with a space) would silently turn the probe
/// into "file not found" and make a finished deployment look unfinished for the whole
/// budget. The probe is read-only and always exits 0, so only its stdout decides.
pub(crate) fn marker_probe_command() -> String {
    format!(r#"cmd /c if exist "{GUEST_DEPLOY_MARKER}" echo deployed"#)
}

/// Word the marker probe prints when the marker exists; also the token it is matched on.
pub(crate) const MARKER_PRESENT_TOKEN: &str = "deployed";

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
///
/// The first statement sets `$ErrorActionPreference` so a failing cmdlet ends the query
/// instead of contributing nothing: an empty list reaches [`select_guest_address`] as "this
/// MAC has no address", which points at DHCP instead of at the broken query. It must be a
/// *variable* assignment - the previous spelling `%ErrorActionPreference='Stop'` was parsed
/// as the `ForEach-Object` alias followed by an argument, so the policy was never applied
/// (R216).
pub(crate) const GUEST_IP_QUERY: &str = "$ErrorActionPreference='Stop'; Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object { $mac = $_.MacAddress; Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } | ForEach-Object { '{0} {1}' -f $mac, $_.IPAddress } }";

/// Normalize a MAC address for comparison (`-`, `:` and case are not significant).
pub(crate) fn normalize_mac(mac: &str) -> String {
    crate::utils::normalize_mac(mac)
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

/// Budget for building the seed ISO with `xorriso`.
///
/// The medium holds three small files (a public key, a per-VM host key and the
/// contract), so a healthy run takes milliseconds. Without a budget a stuck
/// `xorriso` — an unreachable network mount under the staging directory, a hung
/// FUSE mount — would block `Machine::init` forever before the first-boot deadline
/// is even started, which is the same class of hang the QMP and SSH budgets close.
pub(crate) const SEED_BUILD_BUDGET: Duration = Duration::from_secs(120);

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
        // Created owner-only, not `create_dir_all` + `chmod`: the seed root is where the
        // guest's SSH host private key is written next, and `create_dir_all` gives it the
        // umask's permissions (0777 under `umask 000`) for as long as the `chmod` has not run.
        // The two `restrict_dir` calls stay: they tighten a directory a previous attempt (or an
        // older version) left behind, and they are the only thing that can.
        crate::utils::create_owner_only_dir_all(&root).with_context(|| {
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
        // This is a private key: it must be owner-only from the moment it exists, not
        // `chmod`ed afterwards — the seed directory's 0700 is a second line of defence, not
        // the guarantee (the guarantee has to hold for this file on its own).
        crate::utils::write_owner_only_atomically(&host_key_path, &host_key.privkey_str)
            .with_context(|| {
                format!(
                    "failed to write Windows seed host key at {}",
                    host_key_path.display()
                )
            })?;

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
        // `xorriso -o` truncates an existing file and keeps its mode, so creating the medium
        // owner-only *first* is what makes the guarantee hold: a file `xorriso` creates
        // itself comes out with the process umask (0644), and the medium carries this VM's
        // host private key. Measured against xorriso 1.5.8: a pre-created `0600` output file
        // is truncated in place and stays `0600`.
        //
        // A leftover from a failed build has to go, but a name that cannot be removed is a
        // reason of its own: swallowing it made `create_owner_only` fail with `EEXIST` and
        // blame its own permissions for a directory (or an unlinkable file) left behind.
        match std::fs::remove_file(&self.iso) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to remove the stale Windows seed ISO {}",
                        self.iso.display()
                    )
                });
            }
        }
        crate::utils::create_owner_only(&self.iso).with_context(|| {
            format!(
                "failed to create the Windows seed ISO {} with owner-only permissions",
                self.iso.display()
            )
        })?;
        debug!("Creating Windows seed ISO with command:\n{:?}", cmd);

        let output = crate::utils::bounded_output(cmd, SEED_BUILD_BUDGET, "build the Windows seed ISO")
            .await
            .with_context(|| {
                "failed to run `xorriso` to build the Windows seed ISO; install the `xorriso` package"
            })?;
        if !output.status.success() {
            bail!(
                "failed to build the Windows seed ISO: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        // The medium carries this VM's host private key, so the mode created above has to
        // survive `xorriso`. Check it here rather than `chmod` it: a `chmod` would hide the
        // fact that the guarantee stopped holding (a future `xorriso` writing through a
        // temporary file and renaming would defeat the pre-creation silently).
        ensure_seed_medium_is_sealed(&self.iso)?;
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

/// Refuse a seed medium that others can read.
///
/// Split out of [`DeploySeed::build`] because `build` needs `xorriso`: the check is the part
/// that must not regress, and it can be exercised on any file.
fn ensure_seed_medium_is_sealed(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = std::fs::metadata(path)
        .with_context(|| format!("failed to stat the Windows seed medium {}", path.display()))?
        .permissions()
        .mode()
        & 0o777;
    anyhow::ensure!(
        mode == 0o600,
        "the Windows seed medium {} is {mode:o}, not 0600: it carries this VM's SSH host \
         private key, so it must be created owner-only before `xorriso` writes into it",
        path.display()
    );
    Ok(())
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

/// Encode a PowerShell script for `powershell -EncodedCommand`.
///
/// Qlean's own probes must not depend on the image's OpenSSH `DefaultShell`. A stock Windows
/// OpenSSH install defaults to `cmd.exe`, where `Get-NetAdapter` or `Copy-Item` are simply
/// "not recognized"; requiring the registry change is a hidden precondition that shows up as
/// a `cmd` error message far from its cause. `-EncodedCommand` takes a base64 UTF-16LE
/// payload, so it works from either default shell and no quoting, `$` or backtick in the
/// script is ever interpreted by the shell in between.
pub(crate) fn powershell_command(script: &str) -> String {
    format!(
        "powershell -NoProfile -NonInteractive -EncodedCommand {}",
        base64_utf16le(script)
    )
}

/// Base64 of the UTF-16LE encoding that `powershell -EncodedCommand` expects.
fn base64_utf16le(script: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let bytes = script
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<u8>>();
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).map_or(0, |b| u32::from(*b));
        let b2 = chunk.get(2).map_or(0, |b| u32::from(*b));
        let triple = (b0 << 16) | (b1 << 8) | b2;
        for index in 0..4 {
            if index <= chunk.len() {
                let shift = 18 - index * 6;
                out.push(ALPHABET[((triple >> shift) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// PowerShell command querying the guest's own adapter addresses.
pub(crate) fn guest_ip_query_command() -> String {
    powershell_command(GUEST_IP_QUERY)
}

/// PowerShell script copying one file, for `Machine::copy`.
///
/// Paths are single-quoted literals, the only PowerShell string form with no
/// interpolation, so `$` or a backtick in a path stays literal instead of expanding.
pub(crate) fn copy_file_script(from: &str, to: &str) -> String {
    format!(
        "Copy-Item -LiteralPath {} -Destination {} -Force",
        powershell_literal(from),
        powershell_literal(to)
    )
}

/// Command `Machine::copy` runs on the guest: [`copy_file_script`] in an encoded PowerShell.
///
/// Wrapping is via `-EncodedCommand`, never `-Command "..."`: the latter would let the outer
/// shell expand `$` in a path such as `C:/Program Files/a$b` before the copy runs.
pub(crate) fn copy_file_command(from: &str, to: &str) -> String {
    powershell_command(&copy_file_script(from, to))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A medium that cannot be replaced is named as such, not blamed on its own permissions.
    ///
    /// `build` removes a leftover from a failed build and used to ignore the outcome: when the
    /// name was taken by a directory (or a file the process could not unlink), `create_owner_only`
    /// failed with `EEXIST` and the message read "failed to create ... with owner-only
    /// permissions", which is the one thing that was not wrong.
    #[tokio::test]
    async fn a_leftover_medium_that_cannot_be_removed_is_named() {
        let parent = tempfile::tempdir().expect("temp dir");
        let dir = parent.path().join("seed");
        std::fs::create_dir_all(dir.join(SEED_ROOT)).expect("seed root");
        let iso = parent.path().join("seed.iso");
        // A directory where the medium belongs: `remove_file` fails with `EISDIR`/`EPERM`,
        // exactly the leftover a crashed build can leave.
        std::fs::create_dir(&iso).expect("a directory in the medium's place");
        let seed = DeploySeed {
            dir,
            iso: iso.clone(),
        };

        let error = seed
            .build()
            .await
            .expect_err("a medium that cannot be replaced must be reported");
        let message = format!("{error:#}");
        assert!(
            message.contains("failed to remove the stale Windows seed ISO"),
            "the reason has to name the removal, not the creation: {message}"
        );
        assert!(
            !message.contains("failed to create the Windows seed ISO"),
            "the creation never ran, so it cannot be the reason: {message}"
        );
        assert!(
            message.contains(&iso.display().to_string()),
            "the path has to be in the message: {message}"
        );
    }

    /// A medium that is simply not there is a new medium, not a failure.
    ///
    /// The stale-removal branch must not turn the ordinary case - no `seed.iso` yet - into an
    /// error. The build then reaches `xorriso`, which is what the message has to be about when
    /// the host does not have it.
    #[tokio::test]
    async fn an_absent_medium_is_a_new_medium_and_not_a_removal_failure() {
        let parent = tempfile::tempdir().expect("temp dir");
        let dir = parent.path().join("seed");
        std::fs::create_dir_all(dir.join(SEED_ROOT)).expect("seed root");
        std::fs::write(
            dir.join(SEED_ROOT).join("authorized_keys"),
            "ssh-ed25519 AAAATEST\n",
        )
        .expect("contents");
        let seed = DeploySeed {
            dir,
            iso: parent.path().join("seed.iso"),
        };

        match seed.build().await {
            // No `xorriso` on this host: the failure is about running it, not about a leftover.
            Err(error) => {
                let message = format!("{error:#}");
                assert!(
                    !message.contains("stale Windows seed ISO"),
                    "an absent medium is not a stale medium: {message}"
                );
                assert!(
                    message.contains("xorriso"),
                    "the failure has to name what it could not run: {message}"
                );
            }
            // A host with `xorriso`: the medium is there, `0600`, and not empty.
            Ok(()) => {
                use std::os::unix::fs::PermissionsExt;
                let iso = parent.path().join("seed.iso");
                let meta = std::fs::metadata(&iso).expect("the built medium");
                assert_eq!(meta.permissions().mode() & 0o777, 0o600);
                assert!(meta.len() > 0, "an empty medium carries nothing");
            }
        }
    }

    /// The staged seed is owner-only, and it is that from the moment each piece exists.
    ///
    /// `stage` used `create_dir_all` and then `chmod`ed: under `umask 000` the seed root
    /// existed as `0777` until the `chmod` ran, and it is the directory the guest's SSH host
    /// private key is written into next. The mode is asserted on a run directory that already
    /// exists with the umask's permissions, because that is the state a previous attempt leaves
    /// behind and the only state a test can produce without changing the process umask.
    #[tokio::test]
    async fn the_staged_seed_is_owner_only_from_the_moment_it_exists() {
        use std::os::unix::fs::PermissionsExt;

        fn mode_of(path: &Path) -> u32 {
            std::fs::metadata(path)
                .unwrap_or_else(|error| panic!("stat {}: {error}", path.display()))
                .permissions()
                .mode()
                & 0o777
        }

        let parent = tempfile::tempdir().expect("temp dir");
        let run_dir = parent.path().join("abc123");
        // A run directory, and a seed root, that a previous attempt left behind with the
        // umask's permissions: `create_dir_all` leaves existing directories alone, so only the
        // `restrict_dir` calls can tighten them.
        let leftover = run_dir.join("seed").join(SEED_ROOT);
        std::fs::create_dir_all(&leftover).expect("leftover seed root");
        for path in [&run_dir, &run_dir.join("seed"), &leftover] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o777))
                .expect("widen the leftover directories");
        }

        let host_key = generate_host_key(&run_dir).expect("host key");
        let seed = DeploySeed::stage(&run_dir, "ssh-ed25519 AAAATEST client\n", &host_key)
            .await
            .expect("staged");

        let root = run_dir.join("seed").join(SEED_ROOT);
        for path in [run_dir.join("seed"), root.clone()] {
            assert_eq!(
                mode_of(&path),
                0o700,
                "the seed directory {} is not owner-only",
                path.display()
            );
        }

        // The private key and the installed public key are owner-only too; a seed medium that
        // is world-readable hands this VM's host key to every local user.
        assert_eq!(mode_of(&root.join("ssh_host_ed25519_key")), 0o600);
        assert_eq!(mode_of(&root.join("authorized_keys")), 0o600);

        // ... and the guest still gets the three files the image contract names.
        let installed = std::fs::read_to_string(root.join("authorized_keys")).expect("keys");
        assert_eq!(
            installed, "ssh-ed25519 AAAATEST client\n",
            "a trailing newline is added once and only once"
        );
        let contract: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("deploy.json")).expect("contract"))
                .expect("the staged contract parses");
        assert_eq!(contract["username"], GUEST_USERNAME);
        assert_eq!(
            std::fs::read_to_string(root.join("ssh_host_ed25519_key")).expect("host key"),
            host_key.privkey_str,
            "the seed carries the same key the host pins"
        );
        assert!(
            seed.iso_path().ends_with("seed.iso"),
            "the medium is where the caller expects it: {:?}",
            seed.iso_path()
        );
    }

    /// The `deploy.json` schema is the only machine-readable part of the image contract.
    ///
    /// An image author reads `username` and `marker` out of that file, so a field rename
    /// (or a changed default) breaks every conforming image silently: the guest task would
    /// install the key for nobody and Qlean would spend the whole 900s deployment budget
    /// reporting "the deployment marker was never observed". The README example is therefore
    /// parsed with the real type and compared to the real contract, so documentation and
    /// code can only change together.
    #[test]
    fn test_the_readme_deploy_json_example_is_the_contract_the_guest_receives() {
        let readme = include_str!("../README.md");
        let section = readme
            .split("#### Windows image contract")
            .nth(1)
            .expect("the README must document the Windows image contract");
        let json = section
            .split("```json")
            .nth(1)
            .and_then(|rest| rest.split("```").next())
            .expect("the image contract must show the deploy.json example in a json block");

        // Parsing with `DeployContract` is what makes the keys part of the contract: an
        // unknown or missing field is an error here, not a surprise on a Windows host.
        let documented: DeployContract = serde_json::from_str(json).unwrap_or_else(|error| {
            panic!("the README deploy.json example is not the contract: {error}")
        });
        assert_eq!(documented, DeployContract::current());

        // The guest sees exactly what `to_vec_pretty` writes; the example must therefore
        // survive the same round trip the deployed file does.
        let serialized = serde_json::to_string_pretty(&DeployContract::current())
            .expect("the contract must serialize");
        let written: DeployContract = serde_json::from_str(&serialized)
            .expect("the deployed deploy.json must parse back into the contract");
        assert_eq!(documented, written);
    }

    #[test]
    fn test_marker_probe_quotes_the_marker_path() {
        let command = marker_probe_command();
        assert!(
            command.contains(r#""C:\ProgramData\qlean\deployed""#),
            "the marker path must be quoted for cmd: {command}"
        );
        assert_eq!(
            command,
            r#"cmd /c if exist "C:\ProgramData\qlean\deployed" echo deployed"#
        );
    }

    #[test]
    fn test_marker_probe_token_is_not_part_of_the_path() {
        // The stdout check must not be satisfiable by the path itself: the token is a
        // separate word after the quoted path, so only a real marker prints it.
        let command = marker_probe_command();
        let after_path = command
            .split('"')
            .nth(2)
            .expect("the quoted path must close");
        assert_eq!(
            after_path.trim(),
            format!("echo {}", MARKER_PRESENT_TOKEN),
            "only the echo word may follow the quoted path: {command}"
        );
    }

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

    /// A medium that others can read carries this VM's host private key: refuse it instead
    /// of `chmod`ing it, because the `chmod` would only hide that the pre-creation stopped
    /// holding.
    #[tokio::test]
    async fn test_a_seed_medium_that_others_can_read_is_refused() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir()?;
        let iso = tmp.path().join("seed.iso");
        // What `xorriso` leaves behind when it creates the file itself (umask 022).
        std::fs::write(&iso, b"seed")?;
        std::fs::set_permissions(&iso, std::fs::Permissions::from_mode(0o644))?;

        let error = ensure_seed_medium_is_sealed(&iso)
            .expect_err("a world-readable seed medium must not be handed to QEMU")
            .to_string();
        assert!(error.contains("644"), "{error}");
        assert!(error.contains("0600"), "{error}");
        std::fs::set_permissions(&iso, std::fs::Permissions::from_mode(0o600))?;
        ensure_seed_medium_is_sealed(&iso).expect("an owner-only seed medium is fine");
        Ok(())
    }

    /// Run `xorriso` the same way [`DeploySeed::build`] does, with a budget.
    async fn xorriso(args: &[&str]) -> Result<std::process::Output> {
        let mut cmd = tokio::process::Command::new("xorriso");
        cmd.args(args);
        let output =
            crate::utils::bounded_output(cmd, SEED_BUILD_BUDGET, "inspect the seed ISO").await?;
        anyhow::ensure!(
            output.status.success(),
            "`xorriso {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
        Ok(output)
    }

    /// Build the seed medium with a **real** `xorriso` and check what the guest will see.
    ///
    /// The unit tests around it only exercise the staging directory and the sealing of a
    /// stand-in file, so nothing here proved that the actual argument list produces a
    /// medium with the documented volume label and the documented `qlean/` layout — the
    /// one thing the image's first-boot task depends on. Ignored because `xorriso` is not
    /// a CI dependency; run it on a host that has it:
    ///
    /// ```text
    /// cargo test --lib -- --ignored windows_seed_medium
    /// ```
    #[tokio::test]
    #[ignore = "needs a real `xorriso` on the host; run with --ignored"]
    async fn test_windows_seed_medium_has_the_documented_label_and_layout() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir()?;
        let (seed, host_key) = stage(tmp.path()).await?;
        seed.build().await?;
        let iso = seed.iso_path().to_string_lossy().into_owned();

        // The medium carries the guest host private key, so the real `xorriso` output must
        // be sealed too — not only the stand-in file the unit test uses.
        let mode = std::fs::metadata(seed.iso_path())?.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "the built seed medium should be 0600, got {mode:o}"
        );

        // The label is what the first-boot task searches for on the guest side.
        let pvd = String::from_utf8_lossy(&xorriso(&["-indev", &iso, "-pvd_info"]).await?.stdout)
            .into_owned();
        assert!(
            pvd.contains(&format!("Volume Id    : {SEED_VOLUME_LABEL}")),
            "the medium must carry the volume label {SEED_VOLUME_LABEL}:\n{pvd}"
        );

        // Windows reads Joliet, not Rock Ridge, so the names must survive that view.
        let listing = String::from_utf8_lossy(
            &xorriso(&[
                "-indev",
                &iso,
                "-rockridge",
                "off",
                "-joliet",
                "on",
                "-ls",
                &format!("/{SEED_ROOT}"),
            ])
            .await?
            .stdout,
        )
        .into_owned();
        for name in ["authorized_keys", "deploy.json", "ssh_host_ed25519_key"] {
            assert!(
                listing.contains(&format!("'{name}'")),
                "the seed root must contain {name} under Joliet:\n{listing}"
            );
        }

        // The bytes on the medium are what the guest installs, so compare them, not the
        // staging directory they came from.
        let extracted = tmp.path().join("extracted");
        xorriso(&[
            "-osirrox",
            "on",
            "-indev",
            &iso,
            "-extract",
            &format!("/{SEED_ROOT}"),
            &extracted.to_string_lossy(),
        ])
        .await?;
        assert_eq!(
            std::fs::read_to_string(extracted.join("authorized_keys"))?,
            format!("{CLIENT_PUBKEY}\n"),
            "the medium must carry the client public key, unchanged"
        );
        assert_eq!(
            std::fs::read_to_string(extracted.join("ssh_host_ed25519_key"))?,
            host_key.privkey_str,
            "the medium must carry this VM's host key byte for byte"
        );
        let contract: DeployContract =
            serde_json::from_str(&std::fs::read_to_string(extracted.join("deploy.json"))?)?;
        assert_eq!(contract, DeployContract::current());
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

    /// The query sets its error policy, so a failing cmdlet cannot look like "no address".
    ///
    /// R216: the constant began with `%ErrorActionPreference='Stop'`. `%` is PowerShell's
    /// alias for `ForEach-Object`, so that token is a command name, not a variable
    /// assignment: the policy was never applied and a `Get-NetAdapter`/`Get-NetIPAddress`
    /// failure simply produced no lines, which `select_guest_address` reports as "this MAC
    /// has no IPv4 address" - a diagnosis that sends the reader to DHCP.
    #[test]
    fn windows_ip_query_stops_at_a_failing_cmdlet() {
        let policy = "$ErrorActionPreference='Stop'";
        assert!(
            GUEST_IP_QUERY.starts_with(policy),
            "the query has to set the policy before it runs anything: {GUEST_IP_QUERY}"
        );
        assert!(
            !GUEST_IP_QUERY.contains("%ErrorActionPreference"),
            "`%ErrorActionPreference` is the `ForEach-Object` alias, not a variable: {GUEST_IP_QUERY}"
        );
        let policy_at = GUEST_IP_QUERY.find(policy).expect("checked above");
        let first_cmdlet = GUEST_IP_QUERY
            .find("Get-NetAdapter")
            .expect("the query lost its adapter enumeration");
        assert!(
            policy_at < first_cmdlet,
            "the policy has to be set before the first cmdlet: {GUEST_IP_QUERY}"
        );
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
    fn windows_copy_script_keeps_interpolation_sensitive_paths_literal() {
        let script = copy_file_script("C:/Program Files/a$b.txt", "C:/Users/qlean/target `x.txt");
        assert_eq!(
            script,
            "Copy-Item -LiteralPath 'C:/Program Files/a$b.txt' -Destination 'C:/Users/qlean/target `x.txt' -Force"
        );
        assert!(!script.contains('"'), "{script}");
    }

    #[test]
    fn windows_copy_command_never_uses_an_interpolating_wrapper() {
        let cmd = copy_file_command("C:/Program Files/a$b.txt", "C:/Users/qlean/dst.txt");
        assert!(
            cmd.starts_with("powershell -NoProfile -NonInteractive -EncodedCommand "),
            "the copy must not depend on the image's default shell: {cmd}"
        );
        // `-Command "..."` would let the outer shell expand `$b` before the copy runs.
        assert!(!cmd.contains("-Command "), "{cmd}");
        assert!(
            !cmd.contains("$b"),
            "the script must be encoded, not quoted: {cmd}"
        );
        assert!(!cmd.contains('"'), "{cmd}");
    }

    /// Decode a base64 payload back to the bytes a real `powershell` would receive.
    ///
    /// Deliberately written as a decoder rather than "encode, then compare with the
    /// encoder": the point of these tests is to check the payload against the encoding
    /// `-EncodedCommand` documents, and comparing an encoder with itself cannot fail.
    fn decode_base64(payload: &str) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buffer = 0u32;
        let mut bits = 0u32;
        for byte in payload.bytes() {
            let value = match byte {
                b'A'..=b'Z' => byte - b'A',
                b'a'..=b'z' => byte - b'a' + 26,
                b'0'..=b'9' => byte - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' => break,
                other => panic!("not base64: {:?}", other as char),
            };
            buffer = (buffer << 6) | u32::from(value);
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((buffer >> bits) as u8);
            }
        }
        out
    }

    /// The text a Windows guest's `powershell -EncodedCommand` would actually run.
    fn decoded_script(command: &str) -> String {
        let payload = command
            .rsplit(' ')
            .next()
            .expect("the command ends with the payload");
        let bytes = decode_base64(payload);
        assert_eq!(
            bytes.len() % 2,
            0,
            "a UTF-16LE payload has an even number of bytes: {bytes:?}"
        );
        let units: Vec<u16> = (0..bytes.len() / 2)
            .map(|index| u16::from_le_bytes([bytes[index * 2], bytes[index * 2 + 1]]))
            .collect();
        String::from_utf16(&units).expect("the payload must be valid UTF-16")
    }

    #[test]
    fn test_base64_utf16le_matches_the_powershell_encoding() {
        // Vectors computed with an independent encoder (`base64.b64encode(text
        // .encode('utf-16-le'))`), not with the function under test.
        let encode = |text: &str| {
            powershell_command(text)
                .rsplit(' ')
                .next()
                .expect("the command ends with the payload")
                .to_string()
        };
        assert_eq!(encode(""), "");
        assert_eq!(encode("f"), "ZgA=");
        assert_eq!(encode("fo"), "ZgBvAA==");
        assert_eq!(encode("foo"), "ZgBvAG8A");
        // A BMP character: UTF-16LE is one unit, so the payload must be `YE8=`, not the
        // three-byte UTF-8 encoding of the same character.
        assert_eq!(encode("\u{4f60}"), "YE8=");
        // A non-BMP character becomes a surrogate pair: `YQA92ADe` is `a`, then the two
        // big-endian-looking halves D83D/DE00 stored little-endian.
        assert_eq!(encode("a\u{1f600}"), "YQA92ADe");
    }

    #[test]
    fn test_the_encoded_payload_is_the_utf16le_bytes_of_the_real_scripts() {
        // Every production probe goes through the same encoder, so these are the real
        // scripts: truncation, double encoding, a missing surrogate half or a payload that
        // is really UTF-8 with an even byte count all show up here.
        for script in [
            GUEST_IP_QUERY.to_string(),
            copy_file_script("C:/Program Files/a$b`c", "C:/Users/qlean/\u{4f60}.txt"),
        ] {
            let command = powershell_command(&script);
            let payload = command
                .rsplit(' ')
                .next()
                .expect("the command ends with the payload");
            let expected = script
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<u8>>();
            assert_eq!(
                decode_base64(payload),
                expected,
                "the payload of {command:?} must be the UTF-16LE bytes of the script"
            );
            assert_eq!(decoded_script(&command), script);
        }
    }

    #[test]
    fn test_guest_ip_query_is_wrapped_for_either_default_shell() {
        let cmd = guest_ip_query_command();
        assert!(
            cmd.starts_with("powershell -NoProfile -NonInteractive -EncodedCommand "),
            "the IP probe must not need a registry change to run: {cmd}"
        );
        assert!(
            !cmd.contains("Get-NetAdapter"),
            "the script must be encoded: {cmd}"
        );
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
