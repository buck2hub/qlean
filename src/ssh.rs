use std::{
    io::ErrorKind,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Result, bail};
use russh::{
    ChannelMsg, Disconnect,
    keys::{
        PrivateKey, PrivateKeyWithHashAlg, PublicKey,
        ssh_key::{LineEnding, private::Ed25519Keypair, rand_core::OsRng},
    },
};
use russh_sftp::{client::SftpSession, protocol::OpenFlags};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::Instant,
};
use tokio_util::sync::CancellationToken;
use tokio_vsock::{VsockAddr, VsockStream};
use tracing::{debug, error, info};

#[derive(Clone, Debug)]
pub struct PersistedSshKeypair {
    pub pubkey_str: String,
    pub _pubkey_path: PathBuf,
    pub privkey_str: String,
    pub privkey_path: PathBuf,
}

impl PersistedSshKeypair {
    // Try to load a keypair from `dir`
    pub fn from_dir(dir: &Path) -> Result<Self> {
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

pub fn get_ssh_key(dir: &Path) -> Result<PersistedSshKeypair> {
    // First try reading an existing keypair from disk.
    // If that fails we'll just create a new one.
    if let Ok(existing_keypair) = PersistedSshKeypair::from_dir(dir) {
        return Ok(existing_keypair);
    }

    let privkey_path = dir.join("id_ed25519");
    let pubkey_path = privkey_path.with_extension("pub");

    let ed25519_keypair = Ed25519Keypair::random(&mut OsRng);

    let pubkey_openssh = PublicKey::from(ed25519_keypair.public).to_openssh()?;
    debug!("Writing SSH public key to {pubkey_path:?}");
    std::fs::write(&pubkey_path, &pubkey_openssh)?;

    let privkey_openssh = PrivateKey::from(ed25519_keypair)
        .to_openssh(LineEnding::default())?
        .to_string();
    debug!("Writing SSH private key to {privkey_path:?}");

    std::fs::write(&privkey_path, &privkey_openssh)?;
    let mut perms = std::fs::metadata(&privkey_path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(&privkey_path, perms)?;

    let keypair = PersistedSshKeypair {
        pubkey_str: pubkey_openssh,
        _pubkey_path: pubkey_path,
        privkey_str: privkey_openssh,
        privkey_path,
    };
    Ok(keypair)
}

#[derive(Debug, Clone)]
struct SshClient {}

// More SSH event handlers can be defined in this trait
//
// In this example, we're only using Channel, so these aren't needed.
impl russh::client::Handler for SshClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// This struct is a convenience wrapper around a russh client that handles the input/output event
/// loop
pub struct Session {
    session: russh::client::Handle<SshClient>,
    // Cached SFTP session for reuse; lazily initialized
    sftp: Option<SftpSession>,
}

impl Session {
    /// Connect to an SSH server via vsock
    async fn connect(
        privkey: PrivateKey,
        cid: u32,
        port: u32,
        timeout: Duration,
        cancel_token: CancellationToken,
    ) -> Result<Self> {
        let config = russh::client::Config {
            keepalive_interval: Some(Duration::from_secs(5)),
            ..<_>::default()
        };

        let config = Arc::new(config);
        let sh = SshClient {};

        let vsock_addr = VsockAddr::new(cid, port);
        let now = Instant::now();
        info!("🔑 Connecting via vsock");
        let mut session = loop {
            // Check for cancellation
            if cancel_token.is_cancelled() {
                info!("SSH connection cancelled during connect loop");
                return Err(anyhow::anyhow!("SSH connection cancelled"));
            }

            tokio::time::sleep(Duration::from_millis(100)).await;

            // Establish vsock connection
            let stream = match VsockStream::connect(vsock_addr).await {
                Ok(stream) => stream,
                Err(ref e) if e.raw_os_error() == Some(19) => {
                    // This is "No such device" but for some reason Rust doesn't have an IO
                    // ErrorKind for it. Meh.
                    if now.elapsed() > timeout {
                        error!(
                            "Reached timeout trying to connect to virtual machine via SSH, aborting"
                        );
                        return Err(anyhow::anyhow!("Timeout"));
                    }
                    continue;
                }
                Err(ref e) => match e.kind() {
                    ErrorKind::TimedOut
                    | ErrorKind::ConnectionRefused
                    | ErrorKind::ConnectionReset => {
                        if now.elapsed() > timeout {
                            error!(
                                "Reached timeout trying to connect to virtual machine via SSH, aborting"
                            );
                            return Err(anyhow::anyhow!("Timeout"));
                        }
                        continue;
                    }
                    e => {
                        error!("Unhandled error occurred: {e}");
                        return Err(anyhow::anyhow!("Unknown error"));
                    }
                },
            };

            // Connect to SSH via vsock stream
            match russh::client::connect_stream(config.clone(), stream, sh.clone()).await {
                Ok(x) => break x,
                Err(russh::Error::IO(ref e)) => {
                    match e.kind() {
                        // The VM is still booting at this point so we're just ignoring these errors
                        // for some time.
                        ErrorKind::ConnectionRefused | ErrorKind::ConnectionReset => {
                            if now.elapsed() > timeout {
                                error!(
                                    "Reached timeout trying to connect to virtual machine via SSH, aborting"
                                );
                                return Err(anyhow::anyhow!("Timeout"));
                            }
                        }
                        e => {
                            error!("Unhandled error occurred: {e}");
                            return Err(anyhow::anyhow!("Unknown error"));
                        }
                    }
                }
                Err(russh::Error::Disconnect) => {
                    if now.elapsed() > timeout {
                        error!(
                            "Reached timeout trying to connect to virtual machine via SSH, aborting"
                        );
                        return Err(anyhow::anyhow!("Timeout"));
                    }
                }
                Err(e) => {
                    error!("Unhandled error occurred: {e}");
                    return Err(anyhow::anyhow!("Unknown error"));
                }
            }
        };
        debug!("Authenticating via SSH");

        // use publickey authentication
        let auth_res = session
            .authenticate_publickey("root", PrivateKeyWithHashAlg::new(Arc::new(privkey), None))
            .await?;

        if !auth_res.success() {
            return Err(anyhow::anyhow!("Authentication (with publickey) failed"));
        }

        Ok(Self {
            session,
            sftp: None,
        })
    }

    /// Open an SFTP session over the existing SSH connection.
    async fn open_sftp(&mut self) -> Result<SftpSession> {
        let channel = self.session.channel_open_session().await?;
        channel.request_subsystem(true, "sftp").await?;
        let sftp = SftpSession::new(channel.into_stream()).await?;
        Ok(sftp)
    }

    /// Get a cached SFTP session, opening one if needed.
    pub async fn get_sftp(&mut self) -> Result<&mut SftpSession> {
        if self.sftp.is_none() {
            let sftp = self.open_sftp().await?;
            self.sftp = Some(sftp);
        }
        Ok(self.sftp.as_mut().expect("SFTP session must exist"))
    }

    /// Call a command via SSH, streaming its output to stdout/stderr.
    pub async fn call(
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
                return Err(anyhow::anyhow!("SSH call cancelled"));
            }

            // Handle one of the possible events:
            tokio::select! {
                // There's an event available on the session channel
                Some(msg) = channel.wait() => {
                    match msg {
                        // Write data to the terminal
                        ChannelMsg::Data { ref data } => {
                            stdout.write_all(data).await?;
                            stdout.flush().await?;
                        }
                        ChannelMsg::ExtendedData { ref data, ext } => {
                            // ext == 1 means it's stderr content
                            // https://github.com/Eugeny/russh/discussions/258
                            if ext == 1 {
                                stderr.write_all(data).await?;
                                stderr.flush().await?;
                            }
                        }
                        // The command has returned an exit code
                        ChannelMsg::ExitStatus { exit_status } => {
                            code = exit_status;
                            channel.eof().await?;
                            break;
                        }
                        _ => {}
                    }
                },
            }
        }
        Ok(code)
    }

    /// Call a command via SSH and capture its output.
    pub async fn call_with_output(
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
                return Err(anyhow::anyhow!("SSH call cancelled"));
            }

            // Handle one of the possible events:
            tokio::select! {
                // There's an event available on the session channel
                Some(msg) = channel.wait() => {
                    match msg {
                        // Write data to the buffer
                        ChannelMsg::Data { ref data } => {
                            stdout.extend_from_slice(data);
                        }
                        ChannelMsg::ExtendedData { ref data, ext } => {
                            // ext == 1 means it's stderr content
                            // https://github.com/Eugeny/russh/discussions/258
                            if ext == 1 {
                                stderr.extend_from_slice(data);
                            }
                        }
                        // The command has returned an exit code
                        ChannelMsg::ExitStatus { exit_status } => {
                            code = exit_status;
                            channel.eof().await?;
                            break;
                        }
                        _ => {}
                    }
                },
            }
        }
        Ok((code, stdout, stderr))
    }

    pub async fn close(&mut self) -> Result<()> {
        self.session
            .disconnect(Disconnect::ByApplication, "", "English")
            .await?;
        Ok(())
    }
}

/// Connect SSH and run a command that checks whether the system is ready for operation.
pub async fn connect_ssh(
    cid: u32,
    timeout: Duration,
    keypair: PersistedSshKeypair,
    cancel_token: CancellationToken,
) -> Result<Session> {
    let privkey = PrivateKey::from_openssh(&keypair.privkey_str)?;

    // Session is a wrapper around a russh client, defined down below.
    let mut ssh = Session::connect(privkey, cid, 22, timeout, cancel_token.clone()).await?;
    info!("✅ Connected");

    // First we'll wait until the system has fully booted up.
    let is_running_exitcode = ssh
        .call(
            "systemctl is-system-running --wait --quiet",
            cancel_token.clone(),
        )
        .await?;
    debug!("systemctl is-system-running --wait exit code {is_running_exitcode}");

    // Allow the --env option to work by allowing SSH to accept all sent environment variables.
    // ssh.call("echo AcceptEnv * >> /etc/ssh/sshd_config").await?;

    Ok(ssh)
}

impl Session {
    /// Recursively create a directory and all of its parent components if they are missing.
    pub async fn create_dir_all<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let path = path.as_ref();
        // Build path incrementally like mkdir -p
        let mut cur = PathBuf::new();
        for comp in path.components() {
            cur.push(comp);
            if cur.as_os_str().is_empty() {
                continue;
            }
            // Limit SFTP borrow scope to avoid conflicts with self in recursion
            let create_res = {
                let sftp = self.get_sftp().await?;
                sftp.create_dir(cur.to_string_lossy()).await
            };
            match create_res {
                Ok(_) => {}
                Err(e) => {
                    let meta_res = {
                        let sftp = self.get_sftp().await?;
                        sftp.metadata(cur.to_string_lossy()).await
                    };
                    if let Ok(attr) = meta_res {
                        if !attr.is_dir() {
                            bail!("Remote path exists and is not a directory: {:?}", cur);
                        }
                    } else {
                        bail!("Failed to create remote directory {:?}: {}", cur, e);
                    }
                }
            }
        }
        Ok(())
    }

    /// Upload a single file via SFTP.
    pub async fn upload_file<P: AsRef<Path>, Q: AsRef<Path>>(
        &mut self,
        local: P,
        remote: Q,
        cancel_token: CancellationToken,
    ) -> anyhow::Result<()> {
        let local = local.as_ref();
        let remote = remote.as_ref();
        let mut src = tokio::fs::File::open(local).await?;
        // Scope SFTP borrow
        let mut dst = {
            let sftp = self.get_sftp().await?;
            sftp.open_with_flags(
                remote.to_string_lossy(),
                OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
            )
            .await?
        };

        let mut buf = vec![0u8; 128 * 1024];
        loop {
            if cancel_token.is_cancelled() {
                return Err(anyhow::anyhow!("Upload cancelled"));
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
    pub async fn download_file<P: AsRef<Path>, Q: AsRef<Path>>(
        &mut self,
        remote: P,
        local: Q,
        cancel_token: CancellationToken,
    ) -> anyhow::Result<()> {
        let remote = remote.as_ref();
        let local = local.as_ref();
        let mut src = {
            let sftp = self.get_sftp().await?;
            sftp.open(remote.to_string_lossy()).await?
        };
        let mut dst = tokio::fs::File::create(local).await?;

        let mut buf = vec![0u8; 128 * 1024];
        loop {
            if cancel_token.is_cancelled() {
                return Err(anyhow::anyhow!("Download cancelled"));
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
    pub async fn walk_remote_dir<P: AsRef<Path>>(
        &mut self,
        root: P,
        follow_links: bool,
        cancel_token: CancellationToken,
    ) -> Result<Vec<RemoteDirEntry>> {
        let root = root.as_ref();
        let mut out = Vec::new();

        // Stat root
        let root_meta = {
            let sftp = self.get_sftp().await?;
            sftp.metadata(root.to_string_lossy()).await?
        };
        let root_type = RemoteFileType::from_attrs(&root_meta);
        out.push(RemoteDirEntry::new(root.to_path_buf(), root_type));

        // If root is not a dir, nothing more to traverse
        if !out[0].file_type.is_dir() {
            return Ok(out);
        }

        // DFS stack of directories to visit
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            if cancel_token.is_cancelled() {
                return Err(anyhow::anyhow!("Walk cancelled"));
            }

            let entries = {
                let sftp = self.get_sftp().await?;
                match sftp.read_dir(dir.to_string_lossy()).await {
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

                let child_path = dir.join(&name);
                let attrs = {
                    let sftp = self.get_sftp().await?;
                    match sftp.metadata(child_path.to_string_lossy()).await {
                        Ok(a) => a,
                        Err(e) => {
                            debug!("Failed to stat {:?}: {}", child_path, e);
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
                        match sftp.read_link(child_path.to_string_lossy()).await {
                            Ok(tp) => PathBuf::from(tp),
                            Err(e) => {
                                bail!("Failed to read_link {:?}: {}", child_path, e);
                            }
                        }
                    };
                    let target_attrs = {
                        let sftp = self.get_sftp().await?;
                        match sftp.metadata(target_path.to_string_lossy()).await {
                            Ok(a) => a,
                            Err(e) => {
                                bail!("Failed to stat symlink target {:?}: {}", target_path, e);
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
}

#[derive(Clone, Debug)]
pub struct RemoteFileType {
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
    pub fn is_dir(&self) -> bool {
        self.is_dir
    }
    pub fn is_file(&self) -> bool {
        self.is_file
    }
    pub fn is_symlink(&self) -> bool {
        self.is_symlink
    }
}

#[derive(Clone, Debug)]
pub struct RemoteDirEntry {
    path: PathBuf,
    file_type: RemoteFileType,
}

impl RemoteDirEntry {
    fn new(path: PathBuf, file_type: RemoteFileType) -> Self {
        Self { path, file_type }
    }
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn file_type(&self) -> &RemoteFileType {
        &self.file_type
    }
}
