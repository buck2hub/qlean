use std::{
    io::ErrorKind,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use russh::{
    ChannelMsg, Disconnect,
    keys::{
        Algorithm, PrivateKey, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate,
        ssh_key::LineEnding,
    },
};
use russh_sftp::{client::SftpSession, protocol::OpenFlags};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::{Instant, sleep},
};
use tokio_util::sync::CancellationToken;
use tokio_vsock::{VsockAddr, VsockStream};
use tracing::{debug, info};

use crate::guest_path::GuestPath;

#[cfg(test)]
mod host_key_window_tests {
    use super::*;

    #[test]
    fn a_pinned_key_mismatch_is_fatal_only_after_deployment() {
        assert!(
            !pinned_key_mismatch_is_fatal(true),
            "a first boot that has not installed the key yet must keep waiting"
        );
        assert!(
            pinned_key_mismatch_is_fatal(false),
            "once deployed, a wrong host key must never be retried"
        );
    }

    #[test]
    fn an_auth_rejection_is_told_apart_from_a_transport_failure() {
        let rejected = anyhow::anyhow!(AUTH_REJECTED).context("connect attempt");
        assert!(is_auth_rejection(&rejected));
        let unreachable = anyhow::anyhow!("Connection refused (os error 111)");
        assert!(!is_auth_rejection(&unreachable));
        // A host key mismatch is a different story and must not be classified as auth.
        let mismatch = anyhow::anyhow!("the guest {}", PINNED_KEY_REJECTED);
        assert!(!is_auth_rejection(&mismatch));
    }

    #[test]
    fn the_auth_message_names_the_install_locations_and_the_blank_password_trap() {
        let addr = "192.168.221.42:22".parse().unwrap();
        let message = auth_rejected_message(addr, Duration::from_secs(900));
        assert!(message.contains("900-second"), "{message}");
        assert!(
            message.contains("administrators_authorized_keys"),
            "{message}"
        );
        assert!(message.contains("PubkeyAuthentication yes"), "{message}");
        assert!(message.contains("blank"), "{message}");
        assert!(message.contains("LimitBlankPasswordUse"), "{message}");
        assert!(message.contains("Windows image contract"), "{message}");
    }

    #[test]
    fn the_pending_key_message_names_the_cause_and_the_contract() {
        let addr = "192.168.221.42:22".parse().unwrap();
        let message = host_key_pending_message(addr, Duration::from_secs(900));
        assert!(message.contains("192.168.221.42:22"), "{message}");
        assert!(message.contains("900-second"), "{message}");
        assert!(message.contains("not the one Qlean"), "{message}");
        assert!(
            message.contains(crate::windows::SEED_VOLUME_LABEL),
            "{message}"
        );
        assert!(message.contains("Windows image contract"), "{message}");
    }
}

#[cfg(test)]
mod budget_tests {
    use super::*;

    #[tokio::test]
    async fn bounded_passes_a_fast_operation_through() {
        let result = bounded(Duration::from_secs(5), "quick", async { Ok(7u8) }).await;
        assert_eq!(result.unwrap(), 7);
    }

    #[tokio::test]
    async fn bounded_passes_the_operation_error_through() {
        let error = bounded(Duration::from_secs(5), "quick", async {
            Err::<u8, _>(anyhow::anyhow!("guest said no"))
        })
        .await
        .expect_err("propagated");
        assert_eq!(error.to_string(), "guest said no");
    }

    #[tokio::test]
    async fn bounded_reports_its_own_limit_rather_than_a_guest_timeout() {
        let started = std::time::Instant::now();
        let error = bounded(Duration::from_millis(50), "Get-NetIPAddress", async {
            tokio::time::sleep(Duration::from_secs(600)).await;
            Ok(1u8)
        })
        .await
        .expect_err("must not wait for the guest");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the wait must be bounded"
        );

        let message = error.to_string();
        assert!(message.contains("Get-NetIPAddress"), "{message}");
        assert!(message.contains("Qlean's own probe limit"), "{message}");
        // The guest command itself is untouched, and saying otherwise would be a lie.
        assert!(message.contains("may still be running"), "{message}");
    }
}

const ERR_EACCES: i32 = 13; // Permission denied
const ERR_ENODEV: i32 = 19; // No such device

#[derive(Clone)]
pub(crate) struct PersistedSshKeypair {
    pub pubkey_str: String,
    pub _pubkey_path: PathBuf,
    pub privkey_str: String,
    pub privkey_path: PathBuf,
}

// The derived `Debug` printed the private key material, and this struct is a field of
// `Machine`: one `{:?}` in a log line or a failed assertion would have published the
// identity that every deployed guest trusts (the test failures below did exactly that
// before this was fixed). Redact it and keep the paths, which are what debugging needs.
impl std::fmt::Debug for PersistedSshKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PersistedSshKeypair")
            .field("pubkey_str", &self.pubkey_str)
            .field("pubkey_path", &self._pubkey_path)
            .field(
                "privkey_str",
                &format_args!("<redacted {} bytes>", self.privkey_str.len()),
            )
            .field("privkey_path", &self.privkey_path)
            .finish()
    }
}

impl PersistedSshKeypair {
    // Try to load a keypair from `dir`
    //
    // Reading the two halves back is not enough to trust them. The private key is the
    // identity that gets installed into the guest's `authorized_keys`, so it has to
    // parse, and the stored public half has to be the one that private key derives.
    // A pair that does not agree is already unusable: handing it to the transport turns
    // it into "permission denied" much later, after the deployment budget is spent,
    // and nothing in that error mentions the key files.
    pub(crate) fn from_dir(dir: &Path) -> Result<Self> {
        let privkey_path = dir.join("id_ed25519");
        let pubkey_path = privkey_path.with_extension("pub");
        let hint = "delete both files to generate a fresh identity; every guest deployed \
                    with the old one will stop accepting this host";
        let privkey_str = std::fs::read_to_string(&privkey_path).with_context(|| {
            format!(
                "failed to read the SSH private key {}: {hint}",
                privkey_path.display()
            )
        })?;
        let pubkey_str = std::fs::read_to_string(&pubkey_path).with_context(|| {
            format!(
                "failed to read the SSH public key {}: {hint}",
                pubkey_path.display()
            )
        })?;

        let keypair = Self {
            pubkey_str,
            _pubkey_path: pubkey_path,
            privkey_str,
            privkey_path,
        };
        keypair.verify()?;
        Ok(keypair)
    }

    /// Reject a private key that does not parse or a public key that does not belong to it.
    ///
    /// The message names both files and the one action that fixes it, because the caller
    /// cannot regenerate a key without invalidating every guest that was deployed with it.
    fn verify(&self) -> Result<()> {
        let private = PrivateKey::from_openssh(&self.privkey_str).with_context(|| {
            format!(
                "the SSH private key {} does not parse as an OpenSSH key: a truncated or \
                 half-written file looks like this. Delete it and its `.pub` sibling to \
                 generate a fresh identity; every guest deployed with the old key will stop \
                 accepting this host",
                self.privkey_path.display()
            )
        })?;
        let derived = private.public_key().to_openssh().with_context(|| {
            format!(
                "failed to derive the public half of the SSH private key {}",
                self.privkey_path.display()
            )
        })?;
        anyhow::ensure!(
            derived.trim() == self.pubkey_str.trim(),
            "the SSH public key {} does not belong to the private key {}: the two files \
             were written by different runs, or one of them was replaced. Delete both to \
             generate a fresh identity; every guest deployed with the old key will stop \
             accepting this host",
            self._pubkey_path.display(),
            self.privkey_path.display()
        );
        Ok(())
    }
}

pub(crate) fn get_ssh_key(dir: &Path) -> Result<PersistedSshKeypair> {
    let privkey_path = dir.join("id_ed25519");

    // A missing keypair is the normal first run. A keypair that exists but cannot be used
    // is not: regenerating it silently would leave every already-deployed guest holding an
    // authorized key that no longer exists, and the only symptom would be a login failure
    // on some later boot.
    if privkey_path.exists() {
        let existing = PersistedSshKeypair::from_dir(dir)?;
        // The identity inside may still be readable by others; the enclosing directory is
        // owner-only, but a key that was created elsewhere (or before the mode was fixed)
        // has to be tightened rather than trusted.
        crate::utils::restrict_file(&existing.privkey_path)?;
        return Ok(existing);
    }

    generate_keypair(&privkey_path)
}

/// Create `path` with owner-only permission *at creation time*.
///
/// `chmod` after the write is a different program: between the two calls the private key
/// exists on disk with the umask's permissions (0644 under the usual 022), and a crash or a
/// failed chmod leaves it that way for good. Creating it with `0600` means no umask can
/// widen it and no window exists.
fn create_private_file(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

/// Write the private key atomically: a crash leaves either the old file or a complete one.
///
/// `std::fs::write` truncates the target in place, so a crash mid-write leaves a partial
/// key that still parses as "some file" and would be used as the identity.
fn write_private_key(path: &Path, contents: &str) -> Result<()> {
    let tmp_path = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp_path);
    let mut tmp = create_private_file(&tmp_path).with_context(|| {
        format!(
            "failed to create the temporary SSH private key {} with owner-only permissions",
            tmp_path.display()
        )
    })?;
    let written = std::io::Write::write_all(&mut tmp, contents.as_bytes())
        .and_then(|()| std::io::Write::flush(&mut tmp))
        .with_context(|| format!("failed to write the SSH private key {}", tmp_path.display()));
    drop(tmp);
    if let Err(error) = written {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(error);
    }
    std::fs::rename(&tmp_path, path).with_context(|| {
        format!(
            "failed to install the SSH private key {} (the complete key is left at {})",
            path.display(),
            tmp_path.display()
        )
    })?;
    Ok(())
}

/// Generate a fresh ed25519 keypair at `privkey_path` (private key) and
/// `<privkey_path>.pub` (OpenSSH public key), both owned by the caller.
///
/// The private key is created with `0600` permissions and appears at its final path only
/// once it is complete, and its material is never logged. The public half is written after
/// the private key so the identity always exists before the file that advertises it.
pub(crate) fn generate_keypair(privkey_path: &Path) -> Result<PersistedSshKeypair> {
    let pubkey_path = privkey_path.with_extension("pub");

    // Use `rand::rng()` (rand 0.10's thread-local CSPRNG) directly: it implements
    // `CryptoRng`, which is what `ssh-key` 0.7's `PrivateKey::random` requires.
    // This matches the pattern used by russh's own tests and avoids the extra
    // `rand_core::OsRng.unwrap_err()` dance that the new `TryRngCore`-only OsRng
    // would otherwise force on us.
    let privkey = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)?;

    let pubkey_openssh = privkey.public_key().to_openssh()?;
    let privkey_openssh = privkey.to_openssh(LineEnding::default())?.to_string();
    debug!("Writing SSH private key to {privkey_path:?}");
    write_private_key(privkey_path, &privkey_openssh)?;
    debug!("Writing SSH public key to {pubkey_path:?}");
    std::fs::write(&pubkey_path, &pubkey_openssh)?;

    Ok(PersistedSshKeypair {
        pubkey_str: pubkey_openssh,
        _pubkey_path: pubkey_path,
        privkey_str: privkey_openssh,
        privkey_path: privkey_path.to_path_buf(),
    })
}

#[derive(Debug, Clone, Default)]
struct SshClient {
    /// Host key the server must present, when the caller knows it in advance.
    ///
    /// Linux guests keep the historical trust-on-first-use behavior (`None`): the
    /// vsock transport is host-local. Windows guests connect over the shared NAT
    /// network, so the per-VM host key generated at deploy time is pinned here.
    expected_host_key: Option<PublicKey>,
}

impl SshClient {
    fn with_pinned_key(expected: Option<PublicKey>) -> Self {
        Self {
            expected_host_key: expected,
        }
    }
}

impl russh::client::Handler for SshClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let Some(expected) = self.expected_host_key.as_ref() else {
            // No pinned key: this transport is host-local (vsock) and cannot be
            // redirected to another machine's sshd.
            return Ok(true);
        };
        match server_public_key {
            PublicKeyOrCertificate::PublicKey { key, .. } => {
                let matches = key == expected;
                if !matches {
                    info!("❌ Refusing SSH connection: presented host key is not the pinned key");
                }
                Ok(matches)
            }
            // A certificate implies a CA we did not pin; never accept it implicitly.
            PublicKeyOrCertificate::Certificate(_) => {
                info!(
                    "❌ Refusing SSH connection: pinned host key was expected but a certificate was presented"
                );
                Ok(false)
            }
        }
    }
}

/// Explain a rejected host key in terms of what the caller can check.
///
/// A pinned key that does not match is a security decision, not a transient failure, so
/// the message must say which endpoint answered, why the key is pinned, and what makes
/// the two disagree — never just `UnknownKey`.
/// Phrase every pinned-key rejection contains.
///
/// The retry loops in [`connect_ssh`] and [`connect_ssh_windows`] must not retry a rejected
/// host key: it is a security decision, not a transient failure, and retrying only replaces
/// the real reason with "still not reachable" after the whole budget is spent. Detection and
/// construction therefore share this one string instead of matching on prose twice.
const PINNED_KEY_REJECTED: &str = "presented an SSH host key that is not the one deployed";

/// Budget for one of Qlean's own guest probes (deploy marker, address query, file copy).
///
/// These run without a user watching them, so a wedged channel has to fail instead of
/// silently consuming the caller's whole budget. It is not a timeout on the guest: user
/// commands through `Machine::exec` stay unbounded, because `sleep 600` or a long package
/// install is a legitimate silent command.
pub(crate) const PROBE_TIMEOUT: Duration = Duration::from_secs(120);

/// Run `operation` with a budget, naming it as Qlean's own limit rather than the guest's.
async fn bounded<T>(
    budget: Duration,
    command: &str,
    operation: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    match tokio::time::timeout(budget, operation).await {
        Ok(result) => result,
        Err(_) => bail!(
            "Qlean gave up on `{command}` after {}s: the SSH channel accepted the command but \
             produced no exit status. This is Qlean's own probe limit, not a timeout inside the \
             guest, so the command may still be running there",
            budget.as_secs()
        ),
    }
}

fn host_key_rejection_message(transport_name: &str, pinned: bool) -> String {
    if pinned {
        format!(
            "The {transport_name} endpoint {PINNED_KEY_REJECTED} for this VM.\n\
             Qlean pins the per-VM Windows host key created during deployment, so either a \
             different guest answers on this address (for example after a DHCP lease moved) or \
             the VM was re-deployed and now has a new key.\n\
             Check that `get_ip` returns this VM's own address; a VM deployed by a different \
             host cannot be reached from here."
        )
    } else {
        format!("The {transport_name} endpoint presented an unexpected SSH host key.")
    }
}

/// Whether a failed connect attempt must not be retried.
///
/// Only a rejected pinned host key is fatal here: a refused connection means sshd is not up
/// yet, while a wrong key means the retry loop can never succeed.
/// Message an SSH server produces when it refuses the client's public key.
pub(crate) const AUTH_REJECTED: &str = "Authentication (with publickey) failed";

/// Whether the server rejected the public key rather than failing to speak SSH.
///
/// `Permission denied` after a successful handshake means the guest is reachable and the
/// client key is not trusted *yet*. During a first boot that is expected; afterwards it is
/// the real cause of the failure and must not be reported as "the guest is not reachable".
fn is_auth_rejection(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.to_string().contains(AUTH_REJECTED))
}

/// Message for a Windows guest that keeps refusing Qlean's public key.
fn auth_rejected_message(addr: std::net::SocketAddr, budget: Duration) -> String {
    format!(
        "the Windows guest at {addr} completed the SSH handshake but rejected Qlean's public \
         key for the whole {}-second budget.\n\
         The first-boot task must install `{}`/authorized_keys where Windows OpenSSH reads it \
         (`C:\\ProgramData\\ssh\\administrators_authorized_keys` for an administrator account, \
         otherwise `%USERPROFILE%\\.ssh\\authorized_keys`) with an ACL that grants only \
         `Administrators`, `SYSTEM` and the file owner, and `sshd_config` must keep \
         `PubkeyAuthentication yes` and `PasswordAuthentication no`.\n\
         Windows also refuses network logon for an account with a *blank* password \
         (`LimitBlankPasswordUse`), which makes public key authentication fail even when the \
         key is installed correctly; give the account a password nobody types and never \
         enable password authentication. See the README \"Windows image contract\"",
        budget.as_secs(),
        crate::windows::SEED_VOLUME_LABEL
    )
}

/// Whether a pinned host key mismatch must end the attempt loop at once.
///
/// After deployment the guest's host key is fixed, so a mismatch is a hard error: the
/// pinned key is the only thing that makes the TCP transport trustworthy, and silently
/// trusting whatever key the guest presents would throw that away.
///
/// While the first boot is still installing Qlean's key, the guest's `sshd` is expected to
/// be in flux (the task rewrites the host key and restarts the service, and the guest may
/// reboot more than once). Aborting on the first mismatch there would discard the entire
/// deployment budget over a state the guest is on its way to leaving, so the mismatch is
/// retried and reported only once the budget is spent, with a message that names it.
fn pinned_key_mismatch_is_fatal(deployment_in_progress: bool) -> bool {
    !deployment_in_progress
}

/// Message for a guest that never adopted Qlean's host key during its first boot.
fn host_key_pending_message(addr: std::net::SocketAddr, budget: Duration) -> String {
    format!(
        "the Windows guest at {addr} answered SSH with a host key that is not the one Qlean \
         deployed, for the whole {}-second connection budget.\n\
         The first-boot task is expected to install Qlean's host key (`ssh_host_ed25519_key` \
         from the `{}` medium) and restart `sshd`; an `sshd` that starts before that task runs \
         serves its own key and can never be verified. See the README \"Windows image \
         contract\", then retry with `spawn` once the guest has finished its first boot",
        budget.as_secs(),
        crate::windows::SEED_VOLUME_LABEL
    )
}

fn is_fatal_connect_error(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.to_string().contains(PINNED_KEY_REJECTED))
}

/// Everything a single SSH connection attempt needs besides the transport itself.
struct ConnectParams {
    username: &'static str,
    timeout: Duration,
    cancel_token: CancellationToken,
    expected_host_key: Option<PublicKey>,
    /// Transport name used in error messages ("vsock", "tcp").
    transport_name: &'static str,
    /// Message used when `timeout` elapses while the guest is still not listening.
    timeout_message: &'static str,
}

/// This struct is a convenience wrapper around a russh client that handles the input/output event
/// loop
pub(crate) struct Session {
    session: russh::client::Handle<SshClient>,
    // Cached SFTP session for reuse; lazily initialized
    sftp: Option<SftpSession>,
}

impl Session {
    /// Connect to an SSH server over a byte stream produced by `open`.
    ///
    /// `open` is retried until `timeout` elapses. Connection errors that only mean
    /// "the guest is not listening yet" are treated as transient, exactly as the
    /// historical vsock path did; everything else is reported immediately.
    async fn connect_over<S, F, Fut>(
        params: ConnectParams,
        privkey: PrivateKey,
        mut open: F,
    ) -> Result<Self>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = std::io::Result<S>>,
    {
        let ConnectParams {
            username,
            timeout,
            cancel_token,
            expected_host_key,
            transport_name,
            timeout_message,
        } = params;
        let config = russh::client::Config {
            keepalive_interval: Some(Duration::from_secs(5)),
            ..<_>::default()
        };

        let config = Arc::new(config);
        let pinned_host_key = expected_host_key.is_some();
        let sh = SshClient::with_pinned_key(expected_host_key);
        let now = Instant::now();
        let mut session = loop {
            // Check for cancellation
            if cancel_token.is_cancelled() {
                bail!("SSH connection cancelled");
            }

            tokio::time::sleep(Duration::from_millis(100)).await;

            // Establish the transport connection
            let connect_budget = timeout
                .saturating_sub(now.elapsed())
                .max(Duration::from_millis(1));
            let stream = match tokio::time::timeout(connect_budget, open()).await {
                Ok(Ok(stream)) => stream,
                Err(_) => {
                    bail!("Timeout while connecting to VM via {transport_name}.");
                }
                Ok(Err(ref e)) if e.raw_os_error() == Some(ERR_EACCES) => {
                    bail!("Permission denied while connecting via {transport_name}: {e}\n");
                }
                Ok(Err(ref e)) if e.raw_os_error() == Some(ERR_ENODEV) => {
                    // ENODEV is commonly observed while QEMU is still booting/initializing the vsock
                    // transport (e.g. the guest CID isn't ready yet). Treat it as transient and retry
                    // until the overall timeout is reached.
                    debug!("SSH {transport_name} connect not ready yet (ENODEV): {e} (will retry)");
                    if now.elapsed() > timeout {
                        bail!("{timeout_message}\n");
                    }
                    continue;
                }
                Ok(Err(ref e)) => match e.kind() {
                    ErrorKind::TimedOut
                    | ErrorKind::ConnectionRefused
                    | ErrorKind::ConnectionReset
                    | ErrorKind::NetworkUnreachable
                    | ErrorKind::AddrNotAvailable => {
                        if now.elapsed() > timeout {
                            bail!("{timeout_message}");
                        }
                        continue;
                    }
                    e => {
                        bail!("SSH {transport_name} connect error: {e}");
                    }
                },
            };

            // Perform the SSH handshake (which also validates the host key)
            let handshake_budget = timeout
                .saturating_sub(now.elapsed())
                .max(Duration::from_millis(1));
            match tokio::time::timeout(
                handshake_budget,
                russh::client::connect_stream(config.clone(), stream, sh.clone()),
            )
            .await
            {
                Ok(Ok(x)) => break x,
                Err(_) => {
                    bail!("Timeout establishing SSH handshake over {transport_name}.");
                }
                Ok(Err(russh::Error::IO(ref e))) => match e.kind() {
                    // The VM is still booting at this point so we're just ignoring these errors
                    // for some time.
                    ErrorKind::ConnectionRefused
                    | ErrorKind::ConnectionReset
                    | ErrorKind::UnexpectedEof => {
                        if now.elapsed() > timeout {
                            bail!("Timeout establishing SSH handshake over {transport_name}.");
                        }
                    }
                    e => {
                        bail!("SSH handshake error: {e}");
                    }
                },
                Ok(Err(russh::Error::Disconnect)) => {
                    if now.elapsed() > timeout {
                        bail!("Timeout establishing SSH handshake over {transport_name}.");
                    }
                }
                // russh reports a rejected `check_server_key` as `UnknownKey`, which on
                // its own does not say which check failed or what the caller can do.
                Ok(Err(russh::Error::UnknownKey)) => {
                    bail!(
                        "{}",
                        host_key_rejection_message(transport_name, pinned_host_key)
                    );
                }
                Ok(Err(e)) => {
                    bail!("SSH client error: {e}");
                }
            }
        };
        debug!("Authenticating via SSH");
        let auth_budget = timeout
            .saturating_sub(now.elapsed())
            .max(Duration::from_secs(1));
        let auth_res = tokio::time::timeout(
            auth_budget,
            session.authenticate_publickey(
                username,
                PrivateKeyWithHashAlg::new(Arc::new(privkey), None),
            ),
        )
        .await
        .with_context(|| format!("SSH authentication timed out for user {username}"))??;
        if !auth_res.success() {
            bail!("{AUTH_REJECTED}");
        }
        Ok(Self {
            session,
            sftp: None,
        })
    }

    /// Connect to an SSH server via vsock (Linux guests).
    async fn connect(
        privkey: PrivateKey,
        username: &'static str,
        cid: u32,
        port: u32,
        timeout: Duration,
        cancel_token: CancellationToken,
    ) -> Result<Self> {
        let vsock_addr = VsockAddr::new(cid, port);
        Self::connect_over(
            ConnectParams {
                username,
                timeout,
                cancel_token,
                expected_host_key: None,
                transport_name: "vsock",
                timeout_message: "Timeout while connecting to VM via vsock.",
            },
            privkey,
            || VsockStream::connect(vsock_addr),
        )
        .await
    }

    /// Connect to an SSH server over TCP (Windows guests).
    ///
    /// Only used for `GuestOs::Windows`: the guest has no vsock, so the session runs
    /// over the libvirt NAT network, and `expected_host_key` is always pinned to the
    /// per-VM host key that was injected during deployment.
    async fn connect_tcp(
        privkey: PrivateKey,
        username: &'static str,
        addr: std::net::SocketAddr,
        timeout: Duration,
        cancel_token: CancellationToken,
        expected_host_key: PublicKey,
    ) -> Result<Self> {
        Self::connect_over(
            ConnectParams {
                username,
                timeout,
                cancel_token,
                expected_host_key: Some(expected_host_key),
                transport_name: "tcp",
                timeout_message: "Timeout while connecting to VM via tcp.",
            },
            privkey,
            || tokio::net::TcpStream::connect(addr),
        )
        .await
    }

    // NOTE: TCP-based SSH fallback intentionally not supported.
    // Reviewer feedback: avoid architecture changes that introduce non-vsock transports.
    /// Open an SFTP session over the existing SSH connection.
    async fn open_sftp(&mut self) -> Result<SftpSession> {
        let channel = self.session.channel_open_session().await?;
        channel.request_subsystem(true, "sftp").await?;
        let sftp = SftpSession::new(channel.into_stream()).await?;
        Ok(sftp)
    }

    /// Get a cached SFTP session, opening one if needed.
    pub(crate) async fn get_sftp(&mut self) -> Result<&mut SftpSession> {
        if self.sftp.is_none() {
            let sftp = self.open_sftp().await?;
            self.sftp = Some(sftp);
        }
        self.sftp.as_mut().ok_or_else(|| {
            anyhow::anyhow!("the SFTP session could not be opened for this connection")
        })
    }

    /// Call a command via SSH, streaming its output to stdout/stderr.
    pub(crate) async fn call(
        &mut self,
        // env: HashMap<String, String>,
        command: &str,
        cancel_token: CancellationToken,
    ) -> Result<u32> {
        let mut channel = self.session.channel_open_session().await?;

        // for (key, value) in env {
        //     channel.set_env(true, &key, &value).await?;
        // }

        //channel.request_shell(true).await?;
        channel.exec(true, command).await?;

        let code;
        let mut stdout = tokio::io::stdout();
        let mut stderr = tokio::io::stderr();

        loop {
            // Check for cancellation
            if cancel_token.is_cancelled() {
                info!("SSH call cancelled during execution");
                bail!("SSH call cancelled");
            }

            let Some(msg) = channel.wait().await else {
                bail!(
                    "SSH channel closed before exit status for command: {}",
                    command
                );
            };
            match msg {
                // Write data to the terminal
                ChannelMsg::Data { ref data } => {
                    stdout.write_all(data).await?;
                    stdout.flush().await?;
                }
                ChannelMsg::ExtendedData { ref data, ext: 1 } => {
                    // ext == 1 means it's stderr content
                    // https://github.com/Eugeny/russh/discussions/258
                    stderr.write_all(data).await?;
                    stderr.flush().await?;
                }

                // The command has returned an exit code
                ChannelMsg::ExitStatus { exit_status } => {
                    code = exit_status;
                    channel.eof().await?;
                    break;
                }
                _ => {}
            }
        }
        Ok(code)
    }

    /// Call a command via SSH and capture its output.
    pub(crate) async fn call_with_output(
        &mut self,
        command: &str,
        cancel_token: CancellationToken,
    ) -> Result<(u32, Vec<u8>, Vec<u8>)> {
        self.call_with_output_budget(command, cancel_token, None)
            .await
    }

    /// Run one of Qlean's own probes, bounded by [`PROBE_TIMEOUT`].
    pub(crate) async fn call_probe(
        &mut self,
        command: &str,
        cancel_token: CancellationToken,
    ) -> Result<(u32, Vec<u8>, Vec<u8>)> {
        self.call_with_output_budget(command, cancel_token, Some(PROBE_TIMEOUT))
            .await
    }

    async fn call_with_output_budget(
        &mut self,
        command: &str,
        cancel_token: CancellationToken,
        budget: Option<Duration>,
    ) -> Result<(u32, Vec<u8>, Vec<u8>)> {
        match budget {
            Some(budget) => bounded(budget, command, self.run_command(command, cancel_token)).await,
            None => self.run_command(command, cancel_token).await,
        }
    }

    async fn run_command(
        &mut self,
        command: &str,
        cancel_token: CancellationToken,
    ) -> Result<(u32, Vec<u8>, Vec<u8>)> {
        let mut channel = self.session.channel_open_session().await?;
        channel.exec(true, command).await?;

        let code;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        loop {
            // Check for cancellation
            if cancel_token.is_cancelled() {
                info!("SSH call cancelled during execution");
                bail!("SSH call cancelled");
            }

            let Some(msg) = channel.wait().await else {
                bail!(
                    "SSH channel closed before exit status for command: {}",
                    command
                );
            };
            match msg {
                // Write data to the buffer
                ChannelMsg::Data { ref data } => {
                    stdout.extend_from_slice(data);
                }
                ChannelMsg::ExtendedData { ref data, ext: 1 } => {
                    // ext == 1 means it's stderr content
                    // https://github.com/Eugeny/russh/discussions/258
                    stderr.extend_from_slice(data);
                }
                // The command has returned an exit code
                ChannelMsg::ExitStatus { exit_status } => {
                    code = exit_status;
                    channel.eof().await?;
                    break;
                }
                _ => {}
            }
        }
        Ok((code, stdout, stderr))
    }

    pub(crate) async fn close(&mut self) -> Result<()> {
        self.session
            .disconnect(Disconnect::ByApplication, "", "English")
            .await?;
        Ok(())
    }

    /// Open an interactive PTY shell on this SSH session.
    pub(crate) async fn open_shell(
        self,
        cols: u32,
        rows: u32,
        cancel_token: CancellationToken,
    ) -> Result<InteractiveShell> {
        if cancel_token.is_cancelled() {
            bail!("SSH shell cancelled");
        }

        let channel = self.session.channel_open_session().await?;
        channel
            .request_pty(true, "xterm-256color", cols, rows, 0, 0, &[])
            .await?;
        channel.request_shell(true).await?;

        Ok(InteractiveShell {
            session: self,
            channel,
            cancel_token,
        })
    }
}

/// Interactive SSH shell (PTY) over a dedicated vsock session.
pub struct InteractiveShell {
    session: Session,
    channel: russh::Channel<russh::client::Msg>,
    cancel_token: CancellationToken,
}

/// Read half of an [`InteractiveShell`] (for concurrent use with [`InteractiveShellWriter`]).
pub struct InteractiveShellReader {
    read_half: russh::ChannelReadHalf,
    cancel_token: CancellationToken,
}

/// Write half of an [`InteractiveShell`] (stdin / resize / close).
pub struct InteractiveShellWriter {
    session: Session,
    write_half: russh::ChannelWriteHalf<russh::client::Msg>,
    cancel_token: CancellationToken,
}

impl InteractiveShell {
    /// Split into reader and writer halves for concurrent PTY I/O (e.g. `tokio::select!`).
    pub fn split(self) -> (InteractiveShellReader, InteractiveShellWriter) {
        let Self {
            session,
            channel,
            cancel_token,
        } = self;
        let (read_half, write_half) = channel.split();
        (
            InteractiveShellReader {
                read_half,
                cancel_token: cancel_token.clone(),
            },
            InteractiveShellWriter {
                session,
                write_half,
                cancel_token,
            },
        )
    }

    /// Write bytes to the shell stdin.
    pub async fn write(&self, data: &[u8]) -> Result<()> {
        if self.cancel_token.is_cancelled() {
            bail!("SSH shell cancelled");
        }
        self.channel.data_bytes(data.to_vec()).await?;
        Ok(())
    }

    /// Read the next chunk of shell output (stdout and stderr merged).
    ///
    /// Returns `Ok(None)` when the shell has exited or the channel closed.
    pub async fn read_chunk(&mut self) -> Result<Option<Vec<u8>>> {
        let mut buf = Vec::new();
        loop {
            if self.cancel_token.is_cancelled() {
                bail!("SSH shell cancelled");
            }

            let Some(msg) = self.channel.wait().await else {
                return Ok(None);
            };

            match msg {
                ChannelMsg::Data { data } => buf.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, ext: 1 } => buf.extend_from_slice(&data),
                ChannelMsg::ExitStatus { .. } | ChannelMsg::Eof | ChannelMsg::Close => {
                    return Ok(None);
                }
                _ => {}
            }

            if !buf.is_empty() {
                return Ok(Some(buf));
            }
        }
    }

    /// Resize the remote PTY.
    pub async fn resize(&self, cols: u32, rows: u32) -> Result<()> {
        if self.cancel_token.is_cancelled() {
            bail!("SSH shell cancelled");
        }
        self.channel.window_change(cols, rows, 0, 0).await?;
        Ok(())
    }

    /// Close the interactive shell and its dedicated SSH session.
    pub async fn close(self) -> Result<()> {
        let Self {
            mut session,
            channel,
            ..
        } = self;
        let _ = channel.eof().await;
        let _ = channel.close().await;
        let _ = session.close().await;
        Ok(())
    }
}

impl InteractiveShellReader {
    /// Read the next chunk of shell output (stdout and stderr merged).
    ///
    /// Returns `Ok(None)` when the shell has exited or the channel closed.
    pub async fn read_chunk(&mut self) -> Result<Option<Vec<u8>>> {
        let mut buf = Vec::new();
        loop {
            if self.cancel_token.is_cancelled() {
                bail!("SSH shell cancelled");
            }

            let Some(msg) = self.read_half.wait().await else {
                return Ok(None);
            };

            match msg {
                ChannelMsg::Data { data } => buf.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, ext: 1 } => buf.extend_from_slice(&data),
                ChannelMsg::ExitStatus { .. } | ChannelMsg::Eof | ChannelMsg::Close => {
                    return Ok(None);
                }
                _ => {}
            }

            if !buf.is_empty() {
                return Ok(Some(buf));
            }
        }
    }
}

impl InteractiveShellWriter {
    /// Write bytes to the shell stdin.
    pub async fn write(&self, data: &[u8]) -> Result<()> {
        if self.cancel_token.is_cancelled() {
            bail!("SSH shell cancelled");
        }
        self.write_half.data_bytes(data.to_vec()).await?;
        Ok(())
    }

    /// Resize the remote PTY.
    pub async fn resize(&self, cols: u32, rows: u32) -> Result<()> {
        if self.cancel_token.is_cancelled() {
            bail!("SSH shell cancelled");
        }
        self.write_half.window_change(cols, rows, 0, 0).await?;
        Ok(())
    }

    /// Close the interactive shell and its dedicated SSH session.
    pub async fn close(self, _reader: InteractiveShellReader) -> Result<()> {
        let Self {
            mut session,
            write_half,
            ..
        } = self;
        let _ = write_half.eof().await;
        let _ = write_half.close().await;
        let _ = session.close().await;
        Ok(())
    }
}

/// Connect SSH and run a command that checks whether the system is ready for operation.
pub(crate) async fn connect_ssh(
    cid: u32,
    timeout: Duration,
    keypair: PersistedSshKeypair,
    cancel_token: CancellationToken,
    _mac_address: String,
) -> Result<Session> {
    if !std::path::Path::new("/dev/vhost-vsock").exists() {
        bail!("/dev/vhost-vsock is missing. Qlean requires vhost-vsock for SSH (no TCP fallback).")
    }

    let privkey = PrivateKey::from_openssh(&keypair.privkey_str)?;
    let deadline = Instant::now() + timeout;
    let mut last_err: Option<anyhow::Error> = None;

    while Instant::now() < deadline {
        if cancel_token.is_cancelled() {
            bail!("SSH connection cancelled");
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        let per_attempt_timeout = Duration::from_secs(12)
            .min(remaining.max(Duration::from_secs(1)))
            .min(Duration::from_secs(25));

        match Session::connect(
            privkey.clone(),
            "root",
            cid,
            22,
            per_attempt_timeout,
            cancel_token.clone(),
        )
        .await
        {
            Ok(mut session) => {
                info!("✅ Connected via vsock as root");

                let ready_budget = deadline.saturating_duration_since(Instant::now());
                if ready_budget == Duration::ZERO {
                    bail!("SSH connection timed out");
                }

                let _ =
                    tokio::time::timeout(ready_budget, session.call("true", cancel_token.clone()))
                        .await
                        .context("SSH readiness probe timed out")??;

                debug!("SSH command channel is ready");
                return Ok(session);
            }
            Err(e) if is_fatal_connect_error(&e) => return Err(e),
            Err(e) => {
                last_err = Some(e);
                sleep(Duration::from_millis(250)).await;
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("Timeout establishing SSH over vsock.")))
}

/// Connect to a Windows guest over TCP and confirm it is ready for commands.
///
/// The address is discovered by the caller (libvirt DHCP lease lookup by MAC); this
/// function never falls back to a vsock endpoint and never accepts an unpinned host
/// key. `expected_host_key` is the OpenSSH public key generated during deployment.
pub(crate) async fn connect_ssh_windows(
    addr: std::net::SocketAddr,
    timeout: Duration,
    keypair: PersistedSshKeypair,
    cancel_token: CancellationToken,
    expected_host_key: String,
    deployment_in_progress: bool,
) -> Result<Session> {
    let privkey = PrivateKey::from_openssh(&keypair.privkey_str)?;
    let pinned = PublicKey::from_openssh(expected_host_key.trim()).with_context(|| {
        "failed to parse the pinned Windows SSH host key; the deployment seed recorded an invalid key"
    })?;

    let deadline = Instant::now() + timeout;
    let mut last_err: Option<anyhow::Error> = None;
    let mut key_mismatch: Option<anyhow::Error> = None;
    let mut auth_rejected: Option<anyhow::Error> = None;

    while Instant::now() < deadline {
        if cancel_token.is_cancelled() {
            bail!("SSH connection cancelled");
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        let per_attempt_timeout = Duration::from_secs(12)
            .min(remaining.max(Duration::from_secs(1)))
            .min(Duration::from_secs(25));

        match Session::connect_tcp(
            privkey.clone(),
            crate::windows::GUEST_USERNAME,
            addr,
            per_attempt_timeout,
            cancel_token.clone(),
            pinned.clone(),
        )
        .await
        {
            Ok(mut session) => {
                let ready_budget = deadline.saturating_duration_since(Instant::now());
                if ready_budget == Duration::ZERO {
                    bail!("SSH connection timed out");
                }
                let probe = tokio::time::timeout(
                    ready_budget,
                    session
                        .call_with_output(crate::windows::READINESS_COMMAND, cancel_token.clone()),
                )
                .await
                .context("SSH readiness probe timed out")??;
                if probe.0 != 0 {
                    last_err = Some(anyhow::anyhow!(
                        "Windows readiness probe `{}` exited with {}",
                        crate::windows::READINESS_COMMAND,
                        probe.0
                    ));
                    sleep(Duration::from_millis(250)).await;
                    continue;
                }
                info!(
                    "✅ Connected to Windows guest over tcp as {}",
                    crate::windows::GUEST_USERNAME
                );
                return Ok(session);
            }
            Err(e) if is_fatal_connect_error(&e) => {
                if pinned_key_mismatch_is_fatal(deployment_in_progress) {
                    return Err(e);
                }
                key_mismatch = Some(e);
                sleep(Duration::from_millis(250)).await;
            }
            // The guest answered and refused the key: keep waiting (a first boot may not
            // have installed it yet), but remember it, because it is the real story if
            // the budget runs out.
            Err(e) if is_auth_rejection(&e) => {
                auth_rejected = Some(e);
                sleep(Duration::from_millis(250)).await;
            }
            Err(e) => {
                last_err = Some(e);
                sleep(Duration::from_millis(250)).await;
            }
        }
    }

    // A mismatch that outlived the whole budget is the real story; report it instead of
    // the generic "not reachable" message.
    if let Some(mismatch) = key_mismatch {
        return Err(mismatch).context(host_key_pending_message(addr, timeout));
    }
    if let Some(rejected) = auth_rejected {
        return Err(rejected).context(auth_rejected_message(addr, timeout));
    }
    Err(last_err.unwrap_or_else(|| {
        anyhow::anyhow!(
            "Timeout establishing SSH over tcp to {addr}; pass the Windows guest's reachable \
             address and check that sshd accepts the deployed client key"
        )
    }))
}

impl Session {
    /// Recursively create a directory and all of its parent components if they are missing.
    pub(crate) async fn create_dir_all(&mut self, path: &GuestPath) -> Result<()> {
        // Build the path incrementally like mkdir -p, using guest path semantics so a
        // Windows `C:/Users/qlean` never becomes a host-relative `C:/` prefix.
        for cur in path.ancestors() {
            if cur.is_root() {
                // A POSIX "/" and a Windows drive root (`C:`) always exist, and a
                // drive-relative SFTP request for `C:` is not guaranteed to resolve to
                // the drive root, so never try to create (or stat) them.
                continue;
            }
            // Limit SFTP borrow scope to avoid conflicts with self in recursion
            let create_res = {
                let sftp = self.get_sftp().await?;
                sftp.create_dir(cur.as_str()).await
            };
            match create_res {
                Ok(_) => {}
                Err(e) => {
                    let meta_res = {
                        let sftp = self.get_sftp().await?;
                        sftp.metadata(cur.as_str()).await
                    };
                    if let Ok(attr) = meta_res {
                        if !attr.is_dir() {
                            bail!(
                                "Remote path exists and is not a directory: {}",
                                cur.as_str()
                            );
                        }
                    } else {
                        bail!("Failed to create remote directory {}: {}", cur.as_str(), e);
                    }
                }
            }
        }
        Ok(())
    }

    /// Upload a single file via SFTP.
    pub(crate) async fn upload_file(
        &mut self,
        local: &Path,
        remote: &GuestPath,
        cancel_token: CancellationToken,
    ) -> anyhow::Result<()> {
        let mut src = tokio::fs::File::open(local).await?;
        // Scope SFTP borrow
        let mut dst = {
            let sftp = self.get_sftp().await?;
            sftp.open_with_flags(
                remote.as_str(),
                OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
            )
            .await?
        };

        let mut buf = vec![0u8; 128 * 1024];
        loop {
            if cancel_token.is_cancelled() {
                bail!("Upload cancelled");
            }
            let n = AsyncReadExt::read(&mut src, &mut buf).await?;
            if n == 0 {
                break;
            }
            AsyncWriteExt::write_all(&mut dst, &buf[..n]).await?;
        }
        let _ = AsyncWriteExt::flush(&mut dst).await;
        let _ = AsyncWriteExt::shutdown(&mut dst).await;
        Ok(())
    }

    /// Download a single file via SFTP.
    pub(crate) async fn download_file(
        &mut self,
        remote: &GuestPath,
        local: &Path,
        cancel_token: CancellationToken,
    ) -> anyhow::Result<()> {
        let mut src = {
            let sftp = self.get_sftp().await?;
            sftp.open(remote.as_str()).await?
        };
        let mut dst = tokio::fs::File::create(local).await?;

        let mut buf = vec![0u8; 128 * 1024];
        loop {
            if cancel_token.is_cancelled() {
                bail!("Download cancelled");
            }
            let n = AsyncReadExt::read(&mut src, &mut buf).await?;
            if n == 0 {
                break;
            }
            AsyncWriteExt::write_all(&mut dst, &buf[..n]).await?;
        }
        let _ = AsyncWriteExt::flush(&mut dst).await;
        Ok(())
    }

    /// Walk a remote directory tree over SFTP, similar to walkdir.
    /// Returns a depth-first list of entries including the root.
    pub(crate) async fn walk_remote_dir(
        &mut self,
        root: &GuestPath,
        follow_links: bool,
        cancel_token: CancellationToken,
    ) -> Result<Vec<RemoteDirEntry>> {
        let mut out = Vec::new();

        // Stat root
        let root_meta = {
            let sftp = self.get_sftp().await?;
            sftp.metadata(root.as_str()).await?
        };
        let root_type = RemoteFileType::from_attrs(&root_meta);
        out.push(RemoteDirEntry::new(root.clone(), root_type));

        // If root is not a dir, nothing more to traverse
        if !out[0].file_type.is_dir() {
            return Ok(out);
        }

        // DFS stack of directories to visit
        let mut stack = vec![root.clone()];
        while let Some(dir) = stack.pop() {
            if cancel_token.is_cancelled() {
                bail!("Walk cancelled");
            }

            let entries = {
                let sftp = self.get_sftp().await?;
                match sftp.read_dir(dir.as_str()).await {
                    Ok(e) => e,
                    Err(e) => {
                        // If directory can't be read, skip (best-effort)
                        debug!("Failed to read_dir {:?}: {}", dir, e);
                        continue;
                    }
                }
            };

            for entry in entries {
                let name = entry.file_name();
                if name == "." || name == ".." {
                    continue;
                }

                let child_path = dir.join(&name)?;
                let attrs = {
                    let sftp = self.get_sftp().await?;
                    match sftp.metadata(child_path.as_str()).await {
                        Ok(a) => a,
                        Err(e) => {
                            debug!("Failed to stat {}: {}", child_path.as_str(), e);
                            continue;
                        }
                    }
                };
                let ftype = RemoteFileType::from_attrs(&attrs);
                out.push(RemoteDirEntry::new(child_path.clone(), ftype.clone()));

                if ftype.is_dir() {
                    stack.push(child_path);
                } else if ftype.is_symlink() && follow_links {
                    // If it's a symlink and we're following links, stat the target
                    let target_path = {
                        let sftp = self.get_sftp().await?;
                        match sftp.read_link(child_path.as_str()).await {
                            Ok(tp) => GuestPath::new(child_path.guest_os(), tp)?,
                            Err(e) => {
                                bail!("Failed to read_link {}: {}", child_path.as_str(), e);
                            }
                        }
                    };
                    let target_attrs = {
                        let sftp = self.get_sftp().await?;
                        match sftp.metadata(target_path.as_str()).await {
                            Ok(a) => a,
                            Err(e) => {
                                bail!(
                                    "Failed to stat symlink target {}: {}",
                                    target_path.as_str(),
                                    e
                                );
                            }
                        }
                    };
                    let target_type = RemoteFileType::from_attrs(&target_attrs);
                    if target_type.is_dir() {
                        stack.push(target_path);
                    }
                }
            }
        }

        Ok(out)
    }

    /// Get the primary IP address of the remote machine.
    pub(crate) async fn get_remote_ip(&mut self) -> Result<String> {
        let (code, stdout, _stderr) = self
            .call_with_output("hostname -I | awk '{print $1}'", CancellationToken::new())
            .await?;
        if code != 0 {
            bail!("Failed to get remote IP address, exit code {}", code);
        }
        let ip = String::from_utf8(stdout)?.trim().to_string();
        Ok(ip)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct RemoteFileType {
    is_dir: bool,
    is_file: bool,
    is_symlink: bool,
}

impl RemoteFileType {
    fn from_attrs(attrs: &russh_sftp::protocol::FileAttributes) -> Self {
        Self {
            is_dir: attrs.is_dir(),
            is_file: attrs.file_type().is_file(),
            is_symlink: attrs.file_type().is_symlink(),
        }
    }
    pub(crate) fn is_dir(&self) -> bool {
        self.is_dir
    }
    pub(crate) fn is_file(&self) -> bool {
        self.is_file
    }
    pub(crate) fn is_symlink(&self) -> bool {
        self.is_symlink
    }
}

#[derive(Clone, Debug)]
pub(crate) struct RemoteDirEntry {
    path: GuestPath,
    file_type: RemoteFileType,
}

impl RemoteDirEntry {
    fn new(path: GuestPath, file_type: RemoteFileType) -> Self {
        Self { path, file_type }
    }
    pub(crate) fn path(&self) -> &GuestPath {
        &self.path
    }

    pub(crate) fn file_type(&self) -> &RemoteFileType {
        &self.file_type
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rng;
    use russh::client::Handler;
    use russh::keys::Algorithm;

    fn keypair() -> (PrivateKey, PublicKey) {
        let private = PrivateKey::random(&mut rng(), Algorithm::Ed25519).expect("key generated");
        let public = private.public_key().clone();
        (private, public)
    }

    fn presented(public: &PublicKey) -> PublicKeyOrCertificate {
        PublicKeyOrCertificate::PublicKey {
            key: public.clone(),
            hash_alg: None,
        }
    }

    #[test]
    fn test_host_key_rejection_reports_what_to_check() {
        let pinned = host_key_rejection_message("tcp", true);
        // The diagnostic must name the failed decision and both plausible causes.
        assert!(pinned.contains("not the one deployed"), "{pinned}");
        assert!(pinned.contains("DHCP lease moved"), "{pinned}");
        assert!(pinned.contains("get_ip"), "{pinned}");
        assert!(!pinned.contains("UnknownKey"), "{pinned}");

        let unpinned = host_key_rejection_message("vsock", false);
        assert!(unpinned.contains("unexpected SSH host key"), "{unpinned}");
        assert!(!unpinned.contains("pins the per-VM"), "{unpinned}");
    }

    #[test]
    fn test_a_rejected_pinned_key_is_not_retried() {
        // Retrying a security decision would spend the whole connect budget and then report
        // "still not reachable", so the loops must classify it as fatal.
        let rejected = anyhow::anyhow!(host_key_rejection_message("tcp", true));
        assert!(is_fatal_connect_error(&rejected));

        // It also has to be detected through a context layer, because the loops wrap errors.
        let wrapped = rejected.context("SSH client error");
        assert!(is_fatal_connect_error(&wrapped));

        // A guest whose sshd is not up yet is the transient case and must still be retried.
        assert!(!is_fatal_connect_error(&anyhow::anyhow!(
            "Connection refused (os error 111)"
        )));
        assert!(!is_fatal_connect_error(&anyhow::anyhow!(
            host_key_rejection_message("vsock", false)
        )));
    }

    #[test]
    fn test_user_facing_messages_have_no_runs_of_spaces() {
        // Messages are written across several source lines; a lost continuation leaves a run
        // of spaces in the middle of a sentence. Check every Windows-facing message.
        let messages = [
            host_key_rejection_message("tcp", true),
            host_key_rejection_message("vsock", false),
            crate::windows::deploy_timeout_message(std::time::Duration::from_secs(900)),
        ];
        for message in messages {
            for line in message.lines() {
                assert!(
                    !line.contains("  "),
                    "message line has a run of spaces: {line:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_pinned_host_key_accepts_matching_key() {
        let (_private, public) = keypair();
        let mut client = SshClient::with_pinned_key(Some(public.clone()));
        assert!(client.check_server_key(&presented(&public)).await.unwrap());
    }

    #[tokio::test]
    async fn test_pinned_host_key_rejects_other_key() {
        let (_private, pinned) = keypair();
        let (_other_private, other) = keypair();
        let mut client = SshClient::with_pinned_key(Some(pinned));
        assert!(!client.check_server_key(&presented(&other)).await.unwrap());
    }

    #[tokio::test]
    async fn test_unpinned_host_key_keeps_vsock_trust_on_first_use() {
        // Linux guests talk to a host-local vsock endpoint; the historical
        // behavior (accept the presented key) must be preserved.
        let (_private, public) = keypair();
        let mut client = SshClient::with_pinned_key(None);
        assert!(client.check_server_key(&presented(&public)).await.unwrap());
    }

    #[test]
    fn test_pinned_host_key_roundtrips_through_openssh() {
        let (_private, public) = keypair();
        let openssh = public.to_openssh().expect("public key serializes");
        let parsed = PublicKey::from_openssh(openssh.trim()).expect("public key parses");
        assert_eq!(parsed, public);
    }

    #[tokio::test]
    async fn test_cancelled_connection_does_not_retry() {
        let (private, public) = keypair();
        let cancel = CancellationToken::new();
        cancel.cancel();
        let err = Session::connect_over(
            ConnectParams {
                username: "qlean",
                timeout: Duration::from_secs(5),
                cancel_token: cancel,
                expected_host_key: Some(public),
                transport_name: "tcp",
                timeout_message: "timeout",
            },
            private,
            || async {
                std::io::Result::<tokio::net::TcpStream>::Err(std::io::Error::other("never used"))
            },
        )
        .await
        .err()
        .expect("cancelled connection must fail")
        .to_string();
        assert!(err.contains("cancelled"), "{err}");
    }

    /// The private half is a credential: it must be owner-only from the moment it exists.
    #[test]
    fn test_a_generated_private_key_is_owner_only_and_matches_its_public_half() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("temp dir");
        let keypair = get_ssh_key(dir.path()).expect("keypair generated");

        let mode = std::fs::metadata(&keypair.privkey_path)
            .expect("private key stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "the private key must be owner-only");

        let private = PrivateKey::from_openssh(&keypair.privkey_str).expect("private key parses");
        assert_eq!(
            private
                .public_key()
                .to_openssh()
                .expect("derive public half"),
            keypair.pubkey_str.trim(),
            "the stored public half must be the one the private key derives"
        );
        // A second call is the normal reuse path and must not regenerate the identity.
        let again = get_ssh_key(dir.path()).expect("existing keypair reused");
        assert_eq!(again.privkey_str, keypair.privkey_str);
    }

    /// The identity has to be readable by the program class that uses it, not just by us.
    #[test]
    fn test_the_generated_private_key_is_accepted_by_ssh_keygen() {
        let dir = tempfile::tempdir().expect("temp dir");
        let keypair = get_ssh_key(dir.path()).expect("keypair generated");

        let Ok(output) = std::process::Command::new("ssh-keygen")
            .arg("-y")
            .arg("-f")
            .arg(&keypair.privkey_path)
            .output()
        else {
            // No `ssh-keygen` on this host: say so loudly instead of pretending the
            // independence was established.
            println!("SMOKE-UNAVAILABLE: `ssh-keygen` is not installed, OpenSSH was not consulted");
            return;
        };
        assert!(
            output.status.success(),
            "`ssh-keygen -y` rejected the private key: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let derived = String::from_utf8_lossy(&output.stdout);
        assert_eq!(
            derived.trim(),
            keypair.pubkey_str.trim(),
            "the `.pub` file and the private key must describe the same identity"
        );
    }

    /// A half-present keypair is not a first run: say what to do instead of regenerating.
    #[test]
    fn test_a_half_present_keypair_is_reported_with_a_way_out() {
        let dir = tempfile::tempdir().expect("temp dir");
        let keypair = get_ssh_key(dir.path()).expect("keypair generated");
        std::fs::remove_file(keypair.privkey_path.with_extension("pub"))
            .expect("drop the public half");

        let error = get_ssh_key(dir.path())
            .expect_err("a keypair that lost half of itself must not be silently regenerated")
            .to_string();
        assert!(error.contains("public key"), "{error}");
        assert!(error.contains("delete both files"), "{error}");
        assert!(
            !keypair.privkey_path.with_extension("pub").exists(),
            "nothing may be regenerated behind the user's back"
        );
    }

    /// `Debug` reaches logs and failed assertions; the private key must not travel with it.
    #[test]
    fn test_the_private_key_is_redacted_from_debug_output() {
        let dir = tempfile::tempdir().expect("temp dir");
        let keypair = get_ssh_key(dir.path()).expect("keypair generated");
        let printed = format!("{keypair:?}");

        assert!(
            !printed.contains("PRIVATE KEY"),
            "the private key material must never appear in Debug output: {printed}"
        );
        assert!(
            !printed.contains(&keypair.privkey_str),
            "the private key material must never appear in Debug output: {printed}"
        );
        assert!(printed.contains("<redacted"), "{printed}");
        // What debugging actually needs stays.
        assert!(printed.contains(&keypair.pubkey_str), "{printed}");
        assert!(printed.contains("id_ed25519"), "{printed}");
    }

    /// Two files that must agree are never compared by the filesystem.
    #[test]
    fn test_a_public_key_from_another_run_is_reported_instead_of_used() {
        let dir = tempfile::tempdir().expect("temp dir");
        let keypair = get_ssh_key(dir.path()).expect("keypair generated");

        let other = PrivateKey::random(&mut rng(), Algorithm::Ed25519).expect("other key");
        std::fs::write(
            keypair.privkey_path.with_extension("pub"),
            other.public_key().to_openssh().expect("other public half"),
        )
        .expect("overwrite the public half");

        let error = get_ssh_key(dir.path())
            .expect_err("a public key that does not belong to the private key must not be used")
            .to_string();
        assert!(error.contains("does not belong"), "{error}");
        assert!(error.contains("id_ed25519.pub"), "{error}");
        assert!(error.contains("id_ed25519"), "{error}");
    }

    /// A half-written private key is what a crash during the old non-atomic write left behind.
    #[test]
    fn test_a_truncated_private_key_is_reported_instead_of_reused() {
        let dir = tempfile::tempdir().expect("temp dir");
        let keypair = get_ssh_key(dir.path()).expect("keypair generated");
        let truncated = &keypair.privkey_str[..keypair.privkey_str.len() / 2];
        std::fs::write(&keypair.privkey_path, truncated).expect("truncate the private key");

        let error = get_ssh_key(dir.path())
            .expect_err("a truncated private key must not be handed to the transport")
            .to_string();
        assert!(error.contains("does not parse"), "{error}");
        assert!(error.contains("id_ed25519"), "{error}");
    }

    /// A key left readable by others must be tightened, not trusted.
    #[test]
    fn test_a_loosely_permissioned_private_key_is_tightened_on_reuse() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("temp dir");
        let keypair = get_ssh_key(dir.path()).expect("keypair generated");
        std::fs::set_permissions(
            &keypair.privkey_path,
            std::fs::Permissions::from_mode(0o644),
        )
        .expect("loosen the private key");

        let reused = get_ssh_key(dir.path()).expect("existing keypair reused");
        let mode = std::fs::metadata(&reused.privkey_path)
            .expect("private key stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "a reused private key must be owner-only");
        assert_eq!(reused.privkey_str, keypair.privkey_str);
    }

    /// `chmod` after the write is a different program: the mode has to come from creation,
    /// and the write has to be atomic, or a crash leaves a readable or truncated credential.
    #[test]
    fn test_the_private_key_is_created_owner_only_and_never_chmoded() {
        fn region<'a>(source: &'a str, from: &str, to: &str) -> &'a str {
            let start = source.find(from).expect("region start");
            let rest = &source[start..];
            let end = rest.find(to).expect("region end");
            &rest[..end]
        }

        let source = include_str!("ssh.rs");
        let writer = region(
            source,
            "fn create_private_file",
            "/// Generate a fresh ed25519 keypair",
        );
        assert!(
            !writer.contains("set_permissions") && !writer.contains("set_mode"),
            "the private key mode must come from `OpenOptions::mode`, not from a `chmod` that \
             leaves a window (and a crash) with the umask's permissions"
        );
        assert_eq!(
            writer.matches("0o600").count(),
            1,
            "`0o600` must appear exactly once in the key writer, in the file creation call"
        );
        assert!(
            writer.contains(".mode(0o600)"),
            "the private key must be created with `OpenOptionsExt::mode(0o600)`"
        );
        assert!(
            writer.contains("std::fs::rename(&tmp_path, path)"),
            "the private key must be installed by a rename so a crash cannot leave a partial file"
        );

        let generator = region(
            source,
            "pub(crate) fn generate_keypair",
            "#[derive(Debug, Clone, Default)]",
        );
        assert!(
            !generator.contains("set_permissions") && !generator.contains("set_mode"),
            "`generate_keypair` must not re-introduce a `chmod` after the write"
        );
        assert!(
            generator.contains("write_private_key(privkey_path"),
            "`generate_keypair` must write the private key through `write_private_key`"
        );
    }
}
