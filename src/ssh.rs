use std::{
    io::ErrorKind,
    os::unix::fs::PermissionsExt,
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

const ERR_EACCES: i32 = 13; // Permission denied
const ERR_ENODEV: i32 = 19; // No such device

#[derive(Clone, Debug)]
pub(crate) struct PersistedSshKeypair {
    pub pubkey_str: String,
    pub _pubkey_path: PathBuf,
    pub privkey_str: String,
    pub privkey_path: PathBuf,
}

impl PersistedSshKeypair {
    // Try to load a keypair from `dir`
    pub(crate) fn from_dir(dir: &Path) -> Result<Self> {
        let privkey_path = dir.join("id_ed25519");
        let pubkey_path = privkey_path.with_extension("pub");
        let privkey_str = std::fs::read_to_string(&privkey_path)?;
        let pubkey_str = std::fs::read_to_string(&pubkey_path)?;

        Ok(Self {
            pubkey_str,
            _pubkey_path: pubkey_path,
            privkey_str,
            privkey_path,
        })
    }
}

pub(crate) fn get_ssh_key(dir: &Path) -> Result<PersistedSshKeypair> {
    let privkey_path = dir.join("id_ed25519");

    // First try reading an existing keypair from disk.
    // If that fails we'll just create a new one.
    if let Ok(existing_keypair) = PersistedSshKeypair::from_dir(dir) {
        return Ok(existing_keypair);
    }

    generate_keypair(&privkey_path)
}

/// Generate a fresh ed25519 keypair at `privkey_path` (private key) and
/// `<privkey_path>.pub` (OpenSSH public key), both owned by the caller.
///
/// The private key is written with `0600` permissions before its content is
/// flushed to disk, and its material is never logged.
pub(crate) fn generate_keypair(privkey_path: &Path) -> Result<PersistedSshKeypair> {
    let pubkey_path = privkey_path.with_extension("pub");

    // Use `rand::rng()` (rand 0.10's thread-local CSPRNG) directly: it implements
    // `CryptoRng`, which is what `ssh-key` 0.7's `PrivateKey::random` requires.
    // This matches the pattern used by russh's own tests and avoids the extra
    // `rand_core::OsRng.unwrap_err()` dance that the new `TryRngCore`-only OsRng
    // would otherwise force on us.
    let privkey = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)?;

    let pubkey_openssh = privkey.public_key().to_openssh()?;
    debug!("Writing SSH public key to {pubkey_path:?}");
    std::fs::write(&pubkey_path, &pubkey_openssh)?;

    let privkey_openssh = privkey.to_openssh(LineEnding::default())?.to_string();
    debug!("Writing SSH private key to {privkey_path:?}");

    std::fs::write(privkey_path, &privkey_openssh)?;
    let mut perms = std::fs::metadata(privkey_path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(privkey_path, perms)?;

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
            bail!("Authentication (with publickey) failed");
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
        Ok(self.sftp.as_mut().expect("SFTP session must exist"))
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
) -> Result<Session> {
    let privkey = PrivateKey::from_openssh(&keypair.privkey_str)?;
    let pinned = PublicKey::from_openssh(expected_host_key.trim()).with_context(|| {
        "failed to parse the pinned Windows SSH host key; the deployment seed recorded an invalid key"
    })?;

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
            Err(e) => {
                last_err = Some(e);
                sleep(Duration::from_millis(250)).await;
            }
        }
    }

    Err(last_err.unwrap_or_else(|| {
        anyhow::anyhow!(
            "Timeout establishing SSH over tcp to {addr}; pass the Windows guest's              reachable address and check that sshd accepts the deployed client key"
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
}
