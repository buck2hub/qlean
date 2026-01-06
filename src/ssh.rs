use std::{
    io::ErrorKind,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::Result;
use russh::{
    ChannelMsg, Disconnect,
    keys::{
        PrivateKey, PrivateKeyWithHashAlg, PublicKey,
        ssh_key::{LineEnding, private::Ed25519Keypair, rand_core::OsRng},
    },
};
use tokio::{io::AsyncWriteExt, time::Instant};
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
                        error!("Unhandled error occured: {e}");
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
                            error!("Unhandled error occured: {e}");
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
                    error!("Unhandled error occured: {e}");
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

        Ok(Self { session })
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
