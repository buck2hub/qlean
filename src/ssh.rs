use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
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
mod transfer_tests {
    use super::*;
    use std::{
        io,
        pin::Pin,
        task::{Context as TaskContext, Poll},
    };

    /// A writer that accepts every byte and can be told to fail at the flush or at the close.
    ///
    /// The transfers only ever failed here in the wild: a receiving `File` reports success
    /// while the data is still buffered, so a full disk surfaces at `flush` - exactly the call
    /// the old code wrapped in `let _ =`.
    struct PickyWriter {
        written: Vec<u8>,
        fail: Option<&'static str>,
    }

    impl PickyWriter {
        fn new() -> Self {
            Self {
                written: Vec::new(),
                fail: None,
            }
        }

        fn failing_at(step: &'static str) -> Self {
            Self {
                written: Vec::new(),
                fail: Some(step),
            }
        }

        fn error(&self, step: &'static str) -> Poll<io::Result<()>> {
            if self.fail == Some(step) {
                return Poll::Ready(Err(io::Error::other("no space left on device")));
            }
            Poll::Ready(Ok(()))
        }
    }

    impl tokio::io::AsyncWrite for PickyWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
            self.error("flush")
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
            self.error("close")
        }
    }

    /// Transfer `payload` through `copy_stream` and describe what the caller would see.
    async fn transfer(payload: &[u8], writer: &mut PickyWriter) -> (anyhow::Result<()>, Vec<u8>) {
        let mut src = payload;
        let result = Session::copy_stream(
            &mut src,
            writer,
            "the downloaded copy at /tmp/probe",
            &CancellationToken::new(),
            "Download cancelled",
        )
        .await;
        (result, writer.written.clone())
    }

    /// A flush that fails is a failed transfer, not a successful one with a short file.
    #[tokio::test]
    async fn a_transfer_whose_flush_fails_is_reported_as_a_failure() {
        let (result, written) = transfer(b"hello", &mut PickyWriter::failing_at("flush")).await;
        let error = result.expect_err("a failed flush must not be swallowed");
        let message = format!("{error:#}");
        assert!(
            message.contains("failed to flush the downloaded copy at /tmp/probe"),
            "the failure must name the destination: {message}"
        );
        assert_eq!(
            written, b"hello",
            "the bytes themselves were accepted - that is why the flush is the only report"
        );
    }

    /// A close that fails is a failed transfer too: the guest may not have committed the file.
    #[tokio::test]
    async fn a_transfer_whose_close_fails_is_reported_as_a_failure() {
        let (result, _) = transfer(b"hello", &mut PickyWriter::failing_at("close")).await;
        let error = result.expect_err("a failed close must not be swallowed");
        let message = format!("{error:#}");
        assert!(
            message.contains("failed to close the downloaded copy at /tmp/probe"),
            "the failure must name the destination: {message}"
        );
    }

    /// A healthy transfer still reports success and delivers every byte, in order.
    #[tokio::test]
    async fn a_healthy_transfer_reports_success_and_delivers_every_byte() {
        let payload: Vec<u8> = (0..200_000u32).map(|n| (n % 251) as u8).collect();
        let (result, written) = transfer(&payload, &mut PickyWriter::new()).await;
        result.expect("a healthy transfer must succeed");
        assert_eq!(written.len(), payload.len());
        assert_eq!(written, payload);
    }
}

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
    crate::utils::write_owner_only_atomically(privkey_path, &privkey_openssh)?;
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

#[cfg(test)]
mod exit_signal_tests {
    use super::*;

    /// The source after each `wait().await else`, up to the next one: one region per channel loop.
    ///
    /// A text search over the whole file would answer "does the file mention it" - which one loop
    /// can satisfy while the other keeps dropping the message. These are the loops that wait.
    fn wait_regions(source: &str) -> Vec<&str> {
        let anchor = concat!(".wait().await", " else");
        let mut regions = Vec::new();
        let mut from = 0;
        while let Some(at) = source[from..].find(anchor) {
            let start = from + at;
            let next = source[start + anchor.len()..]
                .find(anchor)
                .map(|more| start + anchor.len() + more)
                .unwrap_or(source.len());
            regions.push(&source[start..next]);
            from = next;
        }
        regions
    }

    /// No loop that waits on a channel can loop forever or end for the wrong reason.
    ///
    /// The two command loops end through [`command_step`] (R204), which is where `exit-signal` is
    /// turned into the reason; the two interactive-shell readers end on `exit-status`, `eof` or
    /// `close` and return `Ok(None)`, so a signal-killed shell is already finished for them -
    /// `eof` follows the signal. Every loop that waits therefore has to name one of those: a
    /// decision that can end it, the signal itself, or the terminator that arrives after one.
    #[test]
    fn every_loop_waiting_for_a_status_can_end_a_signal_killed_command() {
        const SOURCE: &str = include_str!("ssh.rs");
        let decides = concat!("command_", "step(&msg");
        let handles_signal = concat!("ChannelMsg::", "ExitSignal");
        let ends_anyway = concat!("ChannelMsg::", "Eof");

        let loops = wait_regions(SOURCE);
        assert!(
            loops.len() >= 4,
            "only {} loops wait on a channel: the scan is looking at the wrong regions",
            loops.len()
        );
        for (index, block) in loops.iter().enumerate() {
            assert!(
                block.contains(decides)
                    || block.contains(handles_signal)
                    || block.contains(ends_anyway),
                "loop {} waits on a channel but neither decides through the shared function, nor \
                 handles `exit-signal`, nor ends on `eof`: a command the guest killed would be \
                 reported as a dropped connection:\n{block}",
                index + 1
            );
        }
        let deciding = loops.iter().filter(|block| block.contains(decides)).count();
        assert_eq!(
            deciding, 2,
            "`call` and `run_command` are the two loops that wait for a command, and both must \
             decide through the shared function"
        );
    }

    #[test]
    fn a_killed_command_names_the_signal_and_not_the_channel() {
        let message = killed_by_signal(
            "powershell -Command Deploy-Marker",
            &russh::Sig::KILL,
            false,
            "",
        );
        assert!(message.contains("SIGKILL"), "{message}");
        assert!(
            message.contains("powershell -Command Deploy-Marker"),
            "the message must name the command: {message}"
        );
        assert!(
            message.contains("instead of an exit status"),
            "the message must say why there is no code: {message}"
        );
        assert!(
            !message.contains("closed before exit status"),
            "the old sentence blamed the channel: {message}"
        );
        assert!(
            !message.contains("the guest said"),
            "an empty report adds nothing to say: {message}"
        );
    }

    #[test]
    fn the_guest_report_and_core_dump_are_kept_verbatim() {
        let message = killed_by_signal(
            "ql-deploy.ps1",
            &russh::Sig::SEGV,
            true,
            "  Segmentation fault (core dumped)\n",
        );
        assert!(message.contains("SIGSEGV"), "{message}");
        assert!(message.contains("dumped core"), "{message}");
        assert!(
            message.contains("the guest said: Segmentation fault (core dumped)"),
            "the guest's own words are trimmed, not dropped or doubled: {message}"
        );
    }

    #[test]
    fn a_server_specific_signal_keeps_its_own_name() {
        let custom = russh::Sig::Custom("SIGSYS".to_string());
        assert_eq!(signal_name(&custom), "SIGSYS");
        assert!(
            killed_by_signal("cmd", &custom, false, " ").contains("SIGSYS"),
            "a signal outside the RFC list is reported by the name the server sent"
        );
    }

    /// The twelve names RFC 4254 section 6.10 lists, each spelled the way a shell prints it.
    #[test]
    fn every_rfc_signal_has_a_distinct_name() {
        let listed = [
            (russh::Sig::ABRT, "SIGABRT"),
            (russh::Sig::ALRM, "SIGALRM"),
            (russh::Sig::FPE, "SIGFPE"),
            (russh::Sig::HUP, "SIGHUP"),
            (russh::Sig::ILL, "SIGILL"),
            (russh::Sig::INT, "SIGINT"),
            (russh::Sig::KILL, "SIGKILL"),
            (russh::Sig::PIPE, "SIGPIPE"),
            (russh::Sig::QUIT, "SIGQUIT"),
            (russh::Sig::SEGV, "SIGSEGV"),
            (russh::Sig::TERM, "SIGTERM"),
            (russh::Sig::USR1, "SIGUSR1"),
        ];
        let mut seen = std::collections::BTreeSet::new();
        for (signal, expected) in listed {
            assert_eq!(signal_name(&signal), expected);
            assert!(seen.insert(expected), "{expected} is reported twice");
        }
        assert_eq!(seen.len(), 12, "twelve signals, twelve names");
    }
}

/// What `Machine::rename` promises when the destination already exists, without a guest.
///
/// The two guests used to answer that question themselves, so the same call could replace a file
/// on one and fail on the other; the tests below hold Qlean to the answer it now gives instead.
#[cfg(test)]
mod rename_contract_tests {
    use super::*;
    use std::collections::HashMap;

    /// A guest's name table that records every request it is sent.
    #[derive(Default)]
    struct FakeGuest {
        files: HashMap<String, Vec<u8>>,
        ops: Vec<String>,
        fail_probe: bool,
        fail_rename: bool,
    }

    impl FakeGuest {
        fn with(path: &str, contents: &str) -> Self {
            let mut guest = Self::default();
            guest
                .files
                .insert(path.to_string(), contents.as_bytes().to_vec());
            guest
        }
    }

    impl RenameSink for FakeGuest {
        async fn destination_exists(&mut self, at: &str) -> Result<bool> {
            self.ops.push(format!("exists {at}"));
            if self.fail_probe {
                bail!("faked: {at} cannot be read");
            }
            Ok(self.files.contains_key(at))
        }

        async fn rename(&mut self, from: &str, to: &str) -> Result<()> {
            self.ops.push(format!("rename {from} {to}"));
            if self.fail_rename {
                bail!("faked: the guest refuses to rename {from} to {to}");
            }
            let bytes = self
                .files
                .remove(from)
                .ok_or_else(|| anyhow::anyhow!("faked: {from} does not exist"))?;
            self.files.insert(to.to_string(), bytes);
            Ok(())
        }
    }

    /// The defect: the destination was the guest's business, so an occupied name was silently
    /// replaced on one guest and refused on another.
    #[tokio::test]
    async fn a_rename_onto_an_occupied_name_is_refused_before_anything_is_sent() {
        let mut guest = FakeGuest::with("C:/out/final.txt", "the file that is already there");
        guest
            .files
            .insert("C:/out/staged.txt".to_string(), b"the new one".to_vec());

        let error = install_rename(&mut guest, "C:/out/staged.txt", "C:/out/final.txt")
            .await
            .expect_err("an occupied destination must be refused")
            .to_string();

        assert!(
            error.contains("C:/out/final.txt already exists"),
            "the error has to name the destination: {error}"
        );
        assert!(
            error.contains("does not replace it") && error.contains("Remove"),
            "the error has to say that a rename does not replace, and what to do instead: {error}"
        );
        // Nothing was sent: the probe is the last request, and both names still hold what they
        // held. A rename that reached the guest first would have replaced the file already.
        assert_eq!(guest.ops, vec!["exists C:/out/final.txt".to_string()]);
        assert_eq!(
            guest.files.get("C:/out/final.txt").map(Vec::as_slice),
            Some(b"the file that is already there".as_slice())
        );
        assert_eq!(
            guest.files.get("C:/out/staged.txt").map(Vec::as_slice),
            Some(b"the new one".as_slice())
        );
    }

    /// A free destination is exactly one rename, with the guest's own answer passed through.
    #[tokio::test]
    async fn a_rename_onto_a_free_name_is_sent_once() {
        let mut guest = FakeGuest::with("C:/out/staged.txt", "the new one");

        install_rename(&mut guest, "C:/out/staged.txt", "C:/out/final.txt")
            .await
            .expect("a free destination is renamed");

        assert_eq!(
            guest.ops,
            vec![
                "exists C:/out/final.txt".to_string(),
                "rename C:/out/staged.txt C:/out/final.txt".to_string()
            ]
        );
        assert_eq!(
            guest.files.get("C:/out/final.txt").map(Vec::as_slice),
            Some(b"the new one".as_slice())
        );
        assert!(!guest.files.contains_key("C:/out/staged.txt"));
    }

    /// A probe that fails is not a free destination: guessing would replace a file the caller
    /// never agreed to lose.
    #[tokio::test]
    async fn a_destination_that_cannot_be_read_stops_the_rename() {
        let mut guest = FakeGuest::with("C:/out/staged.txt", "the new one");
        guest.fail_probe = true;

        let error = format!(
            "{:#}",
            install_rename(&mut guest, "C:/out/staged.txt", "C:/out/final.txt")
                .await
                .expect_err("an unreadable destination is not a free one")
        );

        assert!(
            error.contains("could replace it"),
            "the error has to say why the rename was not attempted: {error}"
        );
        assert!(
            error.contains("faked: C:/out/final.txt cannot be read"),
            "the guest's own reason has to survive: {error}"
        );
        assert_eq!(
            guest.ops,
            vec!["exists C:/out/final.txt".to_string()],
            "no rename may be sent when the destination is unknown"
        );
    }

    /// A rename the guest refuses is the guest's answer, not a refusal Qlean invented.
    #[tokio::test]
    async fn a_rename_the_guest_refuses_is_reported_unchanged() {
        let mut guest = FakeGuest::with("C:/out/staged.txt", "the new one");
        guest.fail_rename = true;

        let error = format!(
            "{:#}",
            install_rename(&mut guest, "C:/out/staged.txt", "C:/out/final.txt")
                .await
                .expect_err("the guest's refusal has to surface")
        );

        assert!(
            error.contains("faked: the guest refuses to rename"),
            "the guest's reason must not be replaced: {error}"
        );
        assert!(
            !error.contains("does not replace it"),
            "Qlean's own refusal was reported for a rename Qlean did send: {error}"
        );
    }

    /// The public `rename` has no way of its own to reach the guest.
    ///
    /// `Machine::rename` is the only caller that matters, and it is not covered by the fake: a
    /// version that called `sftp.rename` directly would restore the very behaviour above - the
    /// guest deciding - while every test in this module stayed green.
    #[test]
    fn the_machine_rename_cannot_bypass_the_refusal() {
        const MACHINE: &str = include_str!("machine.rs");
        let start = MACHINE
            .find("pub async fn rename<P: AsRef<Path>, Q: AsRef<Path>>")
            .expect("`Machine::rename` is gone");
        let body = &MACHINE[start..];
        let body = &body[..body
            .find("\n    }\n")
            .expect("`Machine::rename` has no end")];

        assert!(
            body.contains("install_rename("),
            "`Machine::rename` no longer goes through the refused-destination contract"
        );
        assert!(
            !body.contains("sftp.rename("),
            "`Machine::rename` sends the request itself, so an occupied destination is decided \
             by the guest again"
        );
        // The probe has to be the whole check: a `try_exists` here would be a second answer to
        // the same question, and the one that is compiled into the contract would be dead.
        assert!(
            !body.contains("try_exists"),
            "`Machine::rename` probes the destination itself instead of leaving it to `install_rename`"
        );
    }
}

#[cfg(test)]
mod upload_staging_tests {
    use super::*;
    use crate::GuestOs;
    use std::{
        collections::HashMap,
        io,
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll},
    };
    use tokio::io::AsyncWrite;

    /// A guest's file table with a memory of what was done to it, and a way to refuse each step.
    #[derive(Default)]
    struct GuestState {
        files: Mutex<HashMap<String, Vec<u8>>>,
        /// Files that currently have an open handle - the guest refuses to rename or delete them.
        open: Mutex<Vec<String>>,
        ops: Mutex<Vec<String>>,
        /// Fail the write once this many bytes have been accepted.
        fail_write_after: Mutex<Option<usize>>,
        fail_remove: Mutex<bool>,
        fail_rename: Mutex<bool>,
    }

    impl GuestState {
        fn files(&self) -> HashMap<String, Vec<u8>> {
            self.files.lock().unwrap().clone()
        }
        fn ops(&self) -> Vec<String> {
            self.ops.lock().unwrap().clone()
        }
        fn staged(&self) -> Vec<String> {
            self.files
                .lock()
                .unwrap()
                .keys()
                .filter(|name| name.contains("qlean-upload"))
                .cloned()
                .collect()
        }
    }

    #[derive(Clone, Default)]
    struct FakeGuest(Arc<GuestState>);

    struct FakeWriter {
        guest: Arc<GuestState>,
        at: String,
        buf: Vec<u8>,
        limit: Option<usize>,
    }

    impl Drop for FakeWriter {
        fn drop(&mut self) {
            // What the guest is left with is whatever reached it, and the handle is gone by the
            // time the caller can ask for a rename.
            self.guest
                .files
                .lock()
                .unwrap()
                .insert(self.at.clone(), std::mem::take(&mut self.buf));
            self.guest
                .open
                .lock()
                .unwrap()
                .retain(|open| *open != self.at);
        }
    }

    impl AsyncWrite for FakeWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            if let Some(limit) = self.limit
                && self.buf.len() + data.len() > limit
            {
                let take = limit.saturating_sub(self.buf.len());
                self.buf.extend_from_slice(&data[..take]);
                return Poll::Ready(Err(io::Error::other("no space left on device (faked)")));
            }
            self.buf.extend_from_slice(data);
            Poll::Ready(Ok(data.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl StagedSink for FakeGuest {
        type Writer = FakeWriter;

        async fn open_for_upload(&mut self, at: &str) -> Result<FakeWriter> {
            self.0.ops.lock().unwrap().push(format!("open {at}"));
            self.0.open.lock().unwrap().push(at.to_string());
            self.0
                .files
                .lock()
                .unwrap()
                .insert(at.to_string(), Vec::new());
            let limit = *self.0.fail_write_after.lock().unwrap();
            Ok(FakeWriter {
                guest: Arc::clone(&self.0),
                at: at.to_string(),
                buf: Vec::new(),
                limit,
            })
        }

        async fn exists(&mut self, at: &str) -> Result<bool> {
            self.0.ops.lock().unwrap().push(format!("exists {at}"));
            Ok(self.0.files.lock().unwrap().contains_key(at))
        }

        async fn remove(&mut self, at: &str) -> Result<()> {
            self.0.ops.lock().unwrap().push(format!("remove {at}"));
            if *self.0.fail_remove.lock().unwrap() {
                bail!("faked: cannot remove {at}");
            }
            if self.0.open.lock().unwrap().iter().any(|open| open == at) {
                bail!("faked: {at} has an open handle");
            }
            self.0.files.lock().unwrap().remove(at);
            Ok(())
        }

        async fn rename(&mut self, from: &str, to: &str) -> Result<()> {
            self.0
                .ops
                .lock()
                .unwrap()
                .push(format!("rename {from} {to}"));
            if *self.0.fail_rename.lock().unwrap() {
                bail!("faked: cannot rename {from} to {to}");
            }
            // A file with an open handle cannot be renamed - on Windows no handle at all, and
            // `russh-sftp` only sends `CLOSE` when the object is dropped.
            if self.0.open.lock().unwrap().iter().any(|open| open == from) {
                bail!("faked: {from} still has an open handle");
            }
            let mut files = self.0.files.lock().unwrap();
            if files.contains_key(to) {
                // What OpenSSH's sftp-server answers for a standard rename onto an existing name.
                bail!("faked: {to} already exists");
            }
            let bytes = files
                .remove(from)
                .ok_or_else(|| anyhow::anyhow!("faked: {from} does not exist"))?;
            files.insert(to.to_string(), bytes);
            Ok(())
        }
    }

    const WINDOWS_TARGET: &str = r"C:\Users\deploy\out\deploy.json";

    fn target(guest_os: GuestOs) -> GuestPath {
        match guest_os {
            GuestOs::Windows => GuestPath::new(GuestOs::Windows, WINDOWS_TARGET).unwrap(),
            GuestOs::Linux => GuestPath::new(GuestOs::Linux, "/tmp/out/deploy.json").unwrap(),
        }
    }

    async fn upload(
        guest: &mut FakeGuest,
        target: &GuestPath,
        contents: &[u8],
        cancel: &CancellationToken,
    ) -> Result<()> {
        let staged = staged_upload_path(target)?;
        let mut source = contents;
        install_upload(guest, &staged, target, &mut source, cancel).await
    }

    /// The defect: a failed upload left its half under the caller's name.
    #[tokio::test]
    async fn a_failed_upload_leaves_the_target_as_it_was() {
        let mut guest = FakeGuest::default();
        let target = target(GuestOs::Linux);
        guest
            .0
            .files
            .lock()
            .unwrap()
            .insert(target.as_str().to_string(), b"the old deploy.json".to_vec());
        *guest.0.fail_write_after.lock().unwrap() = Some(8);

        let error = upload(
            &mut guest,
            &target,
            b"a much longer new deployment manifest",
            &CancellationToken::new(),
        )
        .await
        .expect_err("a write that ran out of space must not report success");

        assert!(
            format!("{error:#}").contains("failed to write"),
            "{error:#}"
        );
        let files = guest.0.files();
        assert_eq!(
            files.get(target.as_str()).map(Vec::as_slice),
            Some(&b"the old deploy.json"[..]),
            "the target kept neither its old contents nor nothing: {:?}",
            files.get(target.as_str())
        );
        assert!(
            guest.0.staged().is_empty(),
            "the half-written staged file was left behind: {:?}",
            guest.0.staged()
        );
        assert!(
            !guest.0.ops().iter().any(|op| op.starts_with("rename")),
            "a failed upload tried to install: {:?}",
            guest.0.ops()
        );
    }

    #[tokio::test]
    async fn a_cancelled_upload_leaves_the_target_as_it_was() {
        let mut guest = FakeGuest::default();
        let target = target(GuestOs::Windows);
        guest
            .0
            .files
            .lock()
            .unwrap()
            .insert(target.as_str().to_string(), b"old".to_vec());
        let cancel = CancellationToken::new();
        cancel.cancel();

        let error = upload(&mut guest, &target, b"new contents", &cancel)
            .await
            .expect_err("a cancelled upload must not report success");
        assert!(
            format!("{error:#}").contains("Upload cancelled"),
            "{error:#}"
        );
        assert_eq!(
            guest.0.files().get(target.as_str()).map(Vec::as_slice),
            Some(&b"old"[..])
        );
        assert!(guest.0.staged().is_empty(), "{:?}", guest.0.staged());
    }

    /// A failed upload whose half cannot be removed has to say so: the leftover is the only copy.
    #[tokio::test]
    async fn a_half_that_cannot_be_removed_is_named_in_the_error() {
        let mut guest = FakeGuest::default();
        let target = target(GuestOs::Linux);
        *guest.0.fail_write_after.lock().unwrap() = Some(3);
        *guest.0.fail_remove.lock().unwrap() = true;

        let error = upload(
            &mut guest,
            &target,
            b"0123456789",
            &CancellationToken::new(),
        )
        .await
        .expect_err("a failed write must not report success");
        let message = format!("{error:#}");
        assert!(message.contains("failed to write"), "{message}");
        assert!(
            message.contains("incomplete upload at") && message.contains(".qlean-upload-"),
            "the leftover half has to be named: {message}"
        );
        assert_eq!(
            guest.0.staged().len(),
            1,
            "the half is still there, which is exactly what the message says"
        );
        assert!(
            !guest.0.files().contains_key(target.as_str()),
            "nothing may take the target's name"
        );
    }

    #[tokio::test]
    async fn a_complete_upload_replaces_the_target_and_leaves_no_staging_file() {
        for guest_os in [GuestOs::Linux, GuestOs::Windows] {
            let mut guest = FakeGuest::default();
            let target = target(guest_os);
            guest
                .0
                .files
                .lock()
                .unwrap()
                .insert(target.as_str().to_string(), b"old".to_vec());

            upload(&mut guest, &target, b"brand new", &CancellationToken::new())
                .await
                .expect("an upload that fits must install");

            let files = guest.0.files();
            assert_eq!(
                files.get(target.as_str()).map(Vec::as_slice),
                Some(&b"brand new"[..]),
                "{guest_os:?}"
            );
            assert!(
                guest.0.staged().is_empty(),
                "{guest_os:?}: {:?}",
                guest.0.staged()
            );
            assert_eq!(files.len(), 1, "{guest_os:?}: {:?}", files.keys());
        }
    }

    /// An overwrite has to remove the old name first - a standard rename refuses an existing one -
    /// and the remove must happen after the bytes are all there, not before.
    #[tokio::test]
    async fn an_overwrite_removes_the_old_name_only_after_the_bytes_arrived() {
        let mut guest = FakeGuest::default();
        let target = target(GuestOs::Linux);
        guest
            .0
            .files
            .lock()
            .unwrap()
            .insert(target.as_str().to_string(), b"old".to_vec());

        upload(&mut guest, &target, b"new", &CancellationToken::new())
            .await
            .expect("an overwrite must install");

        let ops = guest.0.ops();
        let open = ops.iter().position(|op| op.starts_with("open ")).unwrap();
        let remove = ops
            .iter()
            .position(|op| op.starts_with(&format!("remove {}", target.as_str())))
            .expect("an overwrite must remove the old name");
        let rename = ops
            .iter()
            .position(|op| op.starts_with("rename "))
            .expect("the staged file must be installed");
        assert!(open < remove, "{ops:?}");
        assert!(remove < rename, "{ops:?}");
    }

    #[tokio::test]
    async fn a_target_that_cannot_be_removed_keeps_the_complete_upload_and_says_where() {
        let mut guest = FakeGuest::default();
        let target = target(GuestOs::Windows);
        guest
            .0
            .files
            .lock()
            .unwrap()
            .insert(target.as_str().to_string(), b"old".to_vec());
        *guest.0.fail_remove.lock().unwrap() = true;

        let error = upload(&mut guest, &target, b"new", &CancellationToken::new())
            .await
            .expect_err("an upload that cannot be installed must not report success");
        let message = format!("{error:#}");
        assert!(message.contains(target.as_str()), "{message}");
        assert!(
            message.contains("qlean-upload") && message.contains(".part"),
            "the message must say where the complete upload is: {message}"
        );
        assert_eq!(
            guest.0.staged().len(),
            1,
            "the complete upload must still be there: {:?}",
            guest.0.staged()
        );
    }

    #[tokio::test]
    async fn a_rename_that_fails_keeps_the_complete_upload_and_says_where() {
        let mut guest = FakeGuest::default();
        let target = target(GuestOs::Linux);
        *guest.0.fail_rename.lock().unwrap() = true;

        let error = upload(&mut guest, &target, b"new", &CancellationToken::new())
            .await
            .expect_err("an upload that cannot be installed must not report success");
        let message = format!("{error:#}");
        assert!(message.contains(".part"), "{message}");
        assert_eq!(guest.0.staged().len(), 1, "{:?}", guest.0.staged());
        assert!(
            !guest.0.files().contains_key(target.as_str()),
            "nothing may take the target's name"
        );
    }

    /// The guest refuses to rename a file that still has an open handle (Windows: any handle).
    #[tokio::test]
    async fn the_staged_file_is_closed_before_it_is_installed() {
        let mut guest = FakeGuest::default();
        let target = target(GuestOs::Windows);
        upload(&mut guest, &target, b"new", &CancellationToken::new())
            .await
            .expect("the writer must be dropped before the rename");
        assert!(
            guest.0.open.lock().unwrap().is_empty(),
            "{:?}",
            guest.0.open.lock().unwrap()
        );
    }

    #[test]
    fn the_staged_name_is_a_short_hidden_sibling_of_the_target() {
        let linux = target(GuestOs::Linux);
        let staged = staged_upload_path(&linux).unwrap();
        assert_eq!(
            staged.parent().map(|parent| parent.as_str().to_string()),
            Some("/tmp/out".to_string())
        );
        assert!(
            staged.as_str().starts_with("/tmp/out/.qlean-upload-"),
            "{}",
            staged.as_str()
        );
        assert!(staged.as_str().ends_with(".part"), "{}", staged.as_str());

        let windows = target(GuestOs::Windows);
        let staged = staged_upload_path(&windows).unwrap();
        // `GuestPath` spells a Windows path with forward slashes, which is what every SFTP call
        // in this crate sends; the staging name is a sibling in that same spelling.
        assert!(
            staged
                .as_str()
                .starts_with("C:/Users/deploy/out/.qlean-upload-"),
            "{}",
            staged.as_str()
        );
        assert_eq!(
            staged.parent().map(|parent| parent.as_str().to_string()),
            Some("C:/Users/deploy/out".to_string())
        );

        // Two uploads to one target never share a staging name.
        let a = staged_upload_path(&linux).unwrap();
        let b = staged_upload_path(&linux).unwrap();
        assert_ne!(a.as_str(), b.as_str());

        // A name at the guest's own limit still has room for the staging suffix.
        let long = GuestPath::new(GuestOs::Linux, format!("/tmp/out/{}", "n".repeat(250))).unwrap();
        let staged = staged_upload_path(&long).unwrap();
        let name = staged.file_name().unwrap();
        assert!(name.len() < 250, "{}", name);
    }

    /// A target directly under a drive root stages in that root.
    ///
    /// R206 stages every upload in a sibling of its target, so the staged name is only
    /// reachable where the target is - which makes the target's parent load-bearing. It used to
    /// be answered differently by the two guests: `/a.txt` -> `/`, but `C:/a.txt` -> `None`
    /// ("the drive branch spelled `C::`"), and this is where a user met it - "cannot upload to
    /// C:/a.txt: it has no directory to stage the bytes in", about a drive root that is a
    /// directory and exists.
    #[test]
    fn a_target_directly_under_a_drive_root_stages_in_that_root() {
        for (guest_os, target_text, expected_parent) in [
            (GuestOs::Linux, "/a.txt", "/"),
            (GuestOs::Windows, "C:/a.txt", "C:"),
        ] {
            let target = GuestPath::new(guest_os, target_text).expect("a valid target");
            let staged = staged_upload_path(&target).unwrap_or_else(|error| {
                panic!("{target_text} has no sibling to stage in: {error:#}")
            });
            assert_eq!(
                staged.parent().map(|parent| parent.as_str().to_string()),
                Some(expected_parent.to_string()),
                "{target_text}"
            );
            assert!(
                staged
                    .file_name()
                    .expect("the staged path has a name")
                    .starts_with(".qlean-upload-"),
                "{}",
                staged.as_str()
            );
        }
    }

    /// The drive-root staging fix is in the changelog, and the code still needs the parent.
    ///
    /// The bug had no failing test and no changelog entry: the staging call answers a missing
    /// parent with a refusal that reads like a guest problem, and nothing tied the sentence a
    /// user sees to the relation that produced it. This guard reads the changelog and the
    /// function, so a later simplification that drops the parent (or a changelog edit that
    /// removes the entry) cannot pass alone.
    #[test]
    fn the_drive_root_staging_fix_is_in_the_changelog_and_the_code() {
        const CHANGELOG: &str = include_str!("../CHANGELOG.md");
        const SSH: &str = include_str!("../src/ssh.rs");

        let unreleased = CHANGELOG
            .split("## [Unreleased]")
            .nth(1)
            .and_then(|rest| rest.split("\n## [").next())
            .expect("the changelog must still have an [Unreleased] section");
        let flat = unreleased.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            flat.contains("An upload to a file directly under a Windows drive root"),
            "the changelog no longer records the drive-root staging failure"
        );
        assert!(
            flat.contains("it has no directory to stage the bytes in"),
            "the changelog must quote the sentence the user met"
        );

        let staged = SSH
            .split("fn staged_upload_path(remote: &GuestPath) -> Result<GuestPath> {")
            .nth(1)
            .expect("`staged_upload_path` is gone")
            .split("\n}\n")
            .next()
            .expect("`staged_upload_path` has no end");
        assert!(
            staged.contains("remote.parent()"),
            "the staged name has to be a sibling of the target, so its parent is load-bearing"
        );
        assert!(
            staged.contains("it has no directory to stage the bytes in"),
            "the refusal a missing parent produces is the sentence the changelog quotes"
        );
    }

    #[test]
    fn the_upload_path_never_truncates_what_it_opens() {
        const SOURCE: &str = include_str!("ssh.rs");
        const MACHINE: &str = include_str!("machine.rs");
        let truncate = concat!("OpenFlags::", "TRUNCATE");
        assert!(
            !SOURCE.contains(truncate),
            "an upload that opens its target with a truncate leaves a half file under that name"
        );
        assert!(
            !MACHINE.contains(truncate),
            "`Machine::write` must stage on the guest too"
        );
        let staged = concat!("install_", "upload(");
        assert!(
            SOURCE.matches(staged).count() >= 3,
            "`upload_file` and `write_file` must both go through the staged protocol"
        );
    }
}

#[cfg(test)]
mod download_staging_tests {
    use super::*;
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };
    use tokio::io::{AsyncRead, ReadBuf};

    /// A reader that hands over one chunk and then fails, like a channel that drops mid-file.
    struct HalfwayThenFails {
        sent: bool,
    }

    impl AsyncRead for HalfwayThenFails {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();
            if this.sent {
                return Poll::Ready(Err(std::io::Error::other("the connection went away")));
            }
            this.sent = true;
            buf.put_slice(b"first half of the hive");
            Poll::Ready(Ok(()))
        }
    }

    /// A reader that keeps producing and cancels the transfer from underneath it.
    struct HalfwayThenCancelled {
        token: CancellationToken,
        sent: bool,
    }

    impl AsyncRead for HalfwayThenCancelled {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();
            if this.sent {
                this.token.cancel();
                buf.put_slice(b"and the rest");
            } else {
                this.sent = true;
                buf.put_slice(b"half");
            }
            Poll::Ready(Ok(()))
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("qlean-download-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch directory");
        dir
    }

    /// Names of the staging files a directory still holds.
    fn leftovers(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .expect("scratch directory")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .filter(|name| name.ends_with(".part"))
            .collect();
        names.sort();
        names
    }

    /// The half that arrived must not be published, and must not survive as a hidden file either.
    #[tokio::test]
    async fn a_failed_download_leaves_the_previous_file_alone() {
        let dir = scratch("failed");
        let local = dir.join("SYSTEM");
        std::fs::write(&local, b"the hive that was already there").expect("previous file");

        let error = Session::place_download(
            &mut HalfwayThenFails { sent: false },
            &local,
            &CancellationToken::new(),
            "the downloaded copy of SYSTEM",
        )
        .await
        .expect_err("a transfer that dies cannot report success");

        assert!(
            error.to_string().contains("the connection went away"),
            "the reason has to survive: {error}"
        );
        assert_eq!(
            std::fs::read(&local).expect("previous file"),
            b"the hive that was already there",
            "the target was truncated by a download that failed"
        );
        assert!(
            leftovers(&dir).is_empty(),
            "the staged half was left behind: {:?}",
            leftovers(&dir)
        );
    }

    #[tokio::test]
    async fn a_cancelled_download_does_not_publish_the_half_it_has() {
        let dir = scratch("cancelled");
        let local = dir.join("SYSTEM");
        std::fs::write(&local, b"the hive that was already there").expect("previous file");
        let token = CancellationToken::new();

        let error = Session::place_download(
            &mut HalfwayThenCancelled {
                token: token.clone(),
                sent: false,
            },
            &local,
            &token,
            "the downloaded copy of SYSTEM",
        )
        .await
        .expect_err("a cancelled transfer cannot report success");

        assert!(error.to_string().contains("Download cancelled"), "{error}");
        assert_eq!(
            std::fs::read(&local).expect("previous file"),
            b"the hive that was already there"
        );
        assert!(leftovers(&dir).is_empty(), "{:?}", leftovers(&dir));
    }

    #[tokio::test]
    async fn a_complete_download_replaces_the_file_and_leaves_no_staging_file() {
        let dir = scratch("complete");
        let local = dir.join("SYSTEM");
        std::fs::write(&local, b"the hive that was already there").expect("previous file");

        Session::place_download(
            &mut &b"a whole hive"[..],
            &local,
            &CancellationToken::new(),
            "the downloaded copy of SYSTEM",
        )
        .await
        .expect("a complete download installs");

        assert_eq!(
            std::fs::read(&local).expect("installed file"),
            b"a whole hive"
        );
        assert!(leftovers(&dir).is_empty(), "{:?}", leftovers(&dir));
    }

    /// Zero bytes is a complete download of an empty file, not a transfer that never ran.
    #[tokio::test]
    async fn an_empty_file_is_a_complete_download_and_does_get_installed() {
        let dir = scratch("empty");
        let local = dir.join("empty.txt");
        std::fs::write(&local, b"stale").expect("previous file");

        Session::place_download(
            &mut &b""[..],
            &local,
            &CancellationToken::new(),
            "the downloaded copy of empty.txt",
        )
        .await
        .expect("an empty file is a complete download");

        assert_eq!(std::fs::read(&local).expect("installed file"), b"");
        assert!(leftovers(&dir).is_empty(), "{:?}", leftovers(&dir));
    }

    /// When the name cannot be taken, the bytes are not thrown away: the error says where they are.
    #[tokio::test]
    async fn installing_over_a_directory_fails_and_says_where_the_complete_download_is() {
        let dir = scratch("install-fails");
        let local = dir.join("occupied");
        std::fs::create_dir(&local).expect("a directory in the way");

        let error = Session::place_download(
            &mut &b"a whole hive"[..],
            &local,
            &CancellationToken::new(),
            "the downloaded copy of occupied",
        )
        .await
        .expect_err("a directory cannot be replaced by a rename");

        let text = error.to_string();
        assert!(text.contains("the complete download is left at"), "{text}");
        assert!(leftovers(&dir).len() == 1, "{:?}", leftovers(&dir));
        assert!(local.is_dir(), "the directory in the way was destroyed");
    }

    #[test]
    fn each_download_stages_in_its_own_sibling() {
        let dir = scratch("staging-names");
        let local = dir.join("disk.qcow2");
        let first = staged_download_path(&local);
        let second = staged_download_path(&local);

        assert_ne!(first, second, "two downloads would share one staged file");
        assert_ne!(first, local);
        assert_eq!(
            first.parent(),
            local.parent(),
            "the rename must not cross a directory"
        );
        let name = first
            .file_name()
            .expect("name")
            .to_string_lossy()
            .into_owned();
        assert!(
            name.starts_with('.'),
            "a running download is not listed: {name}"
        );
        assert!(name.ends_with(".part"), "{name}");
        assert!(
            name.contains("disk.qcow2"),
            "the staged file names what it is: {name}"
        );
    }

    /// `download_file` routes through the staging path, so the tests above speak for it.
    #[test]
    fn the_sftp_download_goes_through_the_staging_path() {
        const SOURCE: &str = include_str!("ssh.rs");
        let opener = concat!("pub(crate) async fn ", "download_file(");
        let start = SOURCE.find(opener).expect("download_file is still here");
        let body = &SOURCE[start..];
        let end = body.find("\n    /// ").unwrap_or(body.len());
        let body = &body[..end];
        assert!(
            body.contains(concat!("place_", "download(")),
            "download_file no longer stages its bytes:\n{body}"
        );
        assert!(
            !body.contains(concat!("File::", "create(")),
            "download_file creates its target directly again, which truncates it:\n{body}"
        );
    }
}

#[cfg(test)]
mod download_tree_tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("qlean-tree-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch directory");
        dir
    }

    /// A staged tree with the shapes a real walk produces: files, nested directories.
    fn staged_tree(dir: &Path) -> PathBuf {
        let staged = staged_download_path(&dir.join("out"));
        std::fs::create_dir_all(staged.join("nested")).expect("staged directory");
        std::fs::write(staged.join("deploy.json"), b"{}").expect("staged file");
        std::fs::write(staged.join("nested/deep.txt"), b"deep").expect("staged file");
        staged
    }

    /// A complete tree takes the caller's name in one step, and the staging name goes away.
    #[test]
    fn a_complete_tree_is_installed_under_the_callers_name() {
        let dir = scratch("complete");
        let local = dir.join("out");
        let staged = staged_tree(&dir);

        install_downloaded_tree(&staged, &local).expect("a complete tree installs");

        assert!(local.is_dir());
        assert_eq!(std::fs::read(local.join("deploy.json")).unwrap(), b"{}");
        assert_eq!(
            std::fs::read(local.join("nested/deep.txt")).unwrap(),
            b"deep"
        );
        assert!(!staged.exists(), "the staging tree stayed behind");
        assert_eq!(
            std::fs::read_dir(&dir).unwrap().count(),
            1,
            "the output directory holds only the answer: {:?}",
            std::fs::read_dir(&dir).unwrap().count()
        );
    }

    /// A tree that never completed leaves nothing under the caller's name, and says so.
    #[test]
    fn a_failed_tree_download_leaves_no_directory_under_the_callers_name() {
        let dir = scratch("failed");
        let local = dir.join("out");
        let staged = staged_tree(&dir);

        let error = abandon_staged_tree(&staged, anyhow::anyhow!("Download cancelled"));

        assert!(error.to_string().contains("Download cancelled"), "{error}");
        assert!(
            !local.exists(),
            "a half tree took the caller's name: {:?}",
            std::fs::read_dir(&local).map(|entries| entries
                .map(|e| e.expect("entry").path())
                .collect::<Vec<_>>())
        );
        assert!(!staged.exists(), "the staged half was left on the disk");
    }

    /// A name that was already there keeps its own files - installing an answer is not a delete.
    #[test]
    fn an_existing_destination_keeps_its_files_and_gains_the_new_tree() {
        let dir = scratch("existing");
        let local = dir.join("out");
        std::fs::create_dir_all(local.join("nested")).expect("existing directory");
        std::fs::write(local.join("local-only.txt"), b"mine").expect("existing file");
        let staged = staged_tree(&dir);

        install_downloaded_tree(&staged, &local)
            .expect("a complete tree merges into an existing one");

        assert_eq!(
            std::fs::read(local.join("local-only.txt")).unwrap(),
            b"mine",
            "installing the tree deleted a file the caller put there"
        );
        assert_eq!(std::fs::read(local.join("deploy.json")).unwrap(), b"{}");
        assert_eq!(
            std::fs::read(local.join("nested/deep.txt")).unwrap(),
            b"deep",
            "a nested entry was not installed into an existing directory"
        );
        assert!(!staged.exists(), "the staging tree stayed behind");
    }

    /// When the tree cannot be installed, the bytes are not thrown away: the error says where.
    #[test]
    fn a_tree_that_cannot_be_installed_says_where_the_complete_download_is() {
        let dir = scratch("occupied");
        let local = dir.join("out");
        std::fs::write(&local, b"a file where a tree has to go").expect("a file in the way");
        let staged = staged_tree(&dir);

        let error = install_downloaded_tree(&staged, &local)
            .expect_err("a file cannot hold an entry of the tree");

        let text = format!("{error:#}");
        assert!(text.contains("the complete download is left at"), "{text}");
        assert_eq!(
            std::fs::read(staged.join("deploy.json")).unwrap(),
            b"{}",
            "the staged tree was emptied by the failed install"
        );
        assert_eq!(
            std::fs::read(&local).unwrap(),
            b"a file where a tree has to go",
            "the file in the way was replaced by a partial install"
        );
    }

    /// A half tree that could not be removed is named: it holds the guest's files.
    #[test]
    fn a_staged_tree_that_cannot_be_removed_is_named_in_the_error() {
        let dir = scratch("unremovable");
        let staged = dir.join("not-a-directory");
        std::fs::write(&staged, b"a file, so removing it as a tree fails").expect("file");

        let error = abandon_staged_tree(&staged, anyhow::anyhow!("Download cancelled"));

        let text = format!("{error:#}");
        assert!(text.contains("Download cancelled"), "{text}");
        assert!(
            text.contains("the partial download could not be removed from"),
            "the error does not say where the half download stayed: {text}"
        );
        assert!(text.contains(&staged.display().to_string()), "{text}");
    }

    /// The directory branch of `download` stages the tree, and never fills the caller's name.
    #[test]
    fn the_directory_download_stages_the_tree_before_it_takes_the_name() {
        const SOURCE: &str = include_str!("machine.rs");
        const CHANGELOG: &str = include_str!("../CHANGELOG.md");

        let start = SOURCE
            .find("pub async fn download<")
            .expect("machine.rs has no download");
        let rest = &SOURCE[start..];
        let end = rest[1..]
            .find("\n    pub async fn ")
            .map(|end| end + 1)
            .unwrap_or(rest.len());
        let body = &rest[..end];

        assert!(
            body.contains(concat!("install_downloaded", "_tree(")),
            "the directory download no longer installs the tree it staged"
        );
        assert!(
            body.contains(concat!("abandon_staged", "_tree(")),
            "a failed tree download no longer throws the staged half away"
        );
        assert!(
            !body.contains(concat!("create_dir_all(&local", "_root)")),
            "the directory download creates the caller's name before the walk finishes, so a \
             failure leaves a partial tree under that name"
        );

        let unreleased = CHANGELOG
            .split("## [Unreleased]")
            .nth(1)
            .and_then(|rest| rest.split("\n## [").next())
            .expect("the changelog must still have an [Unreleased] section");
        let flat = unreleased.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            flat.contains("A directory download that failed"),
            "the changelog no longer records the partial-tree download"
        );
    }
}

#[cfg(test)]
mod command_step_tests {
    use super::*;

    /// The real `ChannelMsg` variant, not an argument list of my own choosing.
    fn exit_signal(signal: russh::Sig, core_dumped: bool, report: &str) -> ChannelMsg {
        ChannelMsg::ExitSignal {
            signal_name: signal,
            core_dumped,
            error_message: report.to_string(),
            lang_tag: "en".to_string(),
        }
    }

    #[test]
    fn an_exit_status_ends_the_loop_with_its_code() {
        assert_eq!(
            command_step(
                &ChannelMsg::ExitStatus { exit_status: 7 },
                "powershell -Command exit 7"
            ),
            CommandStep::Finished(7)
        );
        assert_eq!(
            command_step(&ChannelMsg::ExitStatus { exit_status: 0 }, "true"),
            CommandStep::Finished(0)
        );
    }

    /// The pair that was never proven: the message has to arrive as the *reason*.
    ///
    /// Every field is distinct in this message, so a wiring mistake (the guest's report read as
    /// the signal, the core-dump flag ignored) cannot pass for the right one.
    #[test]
    fn an_exit_signal_ends_the_loop_with_the_signal_the_dump_and_the_report() {
        let step = command_step(
            &exit_signal(russh::Sig::KILL, true, "Out of memory: killed process 4120"),
            "powershell -Command ./ql-deploy.ps1",
        );
        let CommandStep::Killed(message) = step else {
            panic!("a signal-killed command must end the loop, got {step:?}");
        };
        assert!(message.contains("SIGKILL"), "{message}");
        assert!(message.contains("dumped core"), "{message}");
        assert!(
            message.contains("Out of memory: killed process 4120"),
            "{message}"
        );
        assert!(
            message.contains("powershell -Command ./ql-deploy.ps1"),
            "{message}"
        );
        assert!(
            !message.contains("closed before exit status"),
            "the channel sentence blamed the transport: {message}"
        );
    }

    #[test]
    fn the_server_name_of_a_signal_outside_the_rfc_list_survives() {
        let step = command_step(
            &exit_signal(russh::Sig::Custom("SIGSYS".to_string()), false, ""),
            "cmd",
        );
        let CommandStep::Killed(message) = step else {
            panic!("expected a killed step, got {step:?}");
        };
        assert!(message.contains("SIGSYS"), "{message}");
        assert!(
            !message.contains("dumped core"),
            "no dump was reported: {message}"
        );
    }

    /// Output and the rest of the traffic must not be mistaken for an ending.
    #[test]
    fn output_and_benign_messages_do_not_end_the_loop() {
        for msg in [
            ChannelMsg::Data {
                data: b"hello".to_vec().into(),
            },
            ChannelMsg::ExtendedData {
                data: b"warning".to_vec().into(),
                ext: 1,
            },
            ChannelMsg::Success,
            ChannelMsg::Eof,
            ChannelMsg::Close,
        ] {
            assert_eq!(command_step(&msg, "cmd"), CommandStep::Output);
        }
    }

    /// Both command loops end through the same decision, so they cannot disagree.
    #[test]
    fn both_command_loops_decide_through_one_function() {
        const SOURCE: &str = include_str!("ssh.rs");
        let call_site = concat!("command_", "step(&msg, command)");
        assert_eq!(
            SOURCE.matches(call_site).count(),
            2,
            "the loops that wait for a status do not both go through the decision function"
        );
    }
}

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

/// Where a download stages its bytes before they take the caller's name.
///
/// A sibling, so the rename that installs it stays inside one directory (and one filesystem); a
/// name of its own per download, so two concurrent downloads to the same target cannot install
/// each other's half. The leading dot keeps a failed transfer out of a `ls` of the output
/// directory while it is still running.
pub(crate) fn staged_download_path(local: &Path) -> PathBuf {
    static DOWNLOADS: AtomicU64 = AtomicU64::new(0);
    let name = local
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "download".to_string());
    local.with_file_name(format!(
        ".{name}.{}-{}.part",
        std::process::id(),
        DOWNLOADS.fetch_add(1, Ordering::Relaxed)
    ))
}

/// Install a fully staged tree download under `local_root`, and make the name durable.
///
/// `download` used to `create_dir_all(local_root)` and then fill that directory file by file, so
/// a walk that failed halfway - a cancelled transfer, a symbolic link it refuses, an unsupported
/// entry, one file that did not arrive - left a *partial* tree under the caller's own name, and
/// nothing on the disk told it from a complete one: the directory existed, it held plausible
/// files, and a half-mirrored `out` directory reads as `out`. `download_file` had the same shape
/// and was fixed by staging each file (see [`Session::place_download`]); a tree is where it costs
/// more, because the tree is the unit callers ask for.
///
/// So the walk fills a hidden sibling directory and the tree takes the caller's name in one step
/// once the last entry arrived. A fresh name is a single rename, so no reader ever sees half of
/// it. A name that already exists keeps the meaning it had: the new tree is merged into it,
/// because replacing it would delete files the caller put there, and this crate does not delete a
/// user's files to install an answer.
pub(crate) fn install_downloaded_tree(staged: &Path, local_root: &Path) -> Result<()> {
    if !local_root.exists() {
        std::fs::rename(staged, local_root).with_context(|| {
            format!(
                "failed to install {} (the complete download is left at {})",
                local_root.display(),
                staged.display()
            )
        })?;
    } else {
        merge_downloaded_tree(staged, local_root)?;
    }
    crate::utils::sync_directory_of(local_root).with_context(|| {
        format!(
            "wrote {} but could not make its directory durable",
            local_root.display()
        )
    })
}

/// Move a staged tree into a directory that already exists, entry by entry.
///
/// The staged tree is emptied as it goes, so the staging directory is gone when this returns and
/// is still the whole answer when it fails - the error names it, which is the one thing a caller
/// with a half-installed tree needs to know.
fn merge_downloaded_tree(staged: &Path, local_root: &Path) -> Result<()> {
    let entries = std::fs::read_dir(staged).with_context(|| {
        format!(
            "failed to read the staged download {} (the complete download is left there)",
            staged.display()
        )
    })?;
    for entry in entries {
        let entry = entry
            .with_context(|| format!("failed to read the staged download {}", staged.display()))?;
        let from = entry.path();
        let to = local_root.join(entry.file_name());
        let metadata = std::fs::symlink_metadata(&from)
            .with_context(|| format!("failed to inspect the staged {}", from.display()))?;
        if metadata.is_dir() {
            std::fs::create_dir_all(&to).with_context(|| {
                format!("failed to create the local directory {}", to.display())
            })?;
            merge_downloaded_tree(&from, &to)?;
        } else {
            // A file (or a link, which this crate never stages) replaces its name in one step.
            std::fs::rename(&from, &to).with_context(|| {
                format!(
                    "failed to install {} (the complete download is left at {})",
                    to.display(),
                    from.display()
                )
            })?;
        }
    }
    std::fs::remove_dir(staged).with_context(|| {
        format!(
            "failed to remove the staging directory {}",
            staged.display()
        )
    })
}

/// Throw away a staged tree that never became an answer, and say where it stayed if it stayed.
///
/// The bytes are not the caller's problem on failure, but a hidden half-mirror that could not be
/// removed is: it holds a copy of the guest's files with no name saying so.
pub(crate) fn abandon_staged_tree(staged: &Path, error: anyhow::Error) -> anyhow::Error {
    match std::fs::remove_dir_all(staged) {
        Ok(()) => error,
        Err(cleanup) if cleanup.kind() == std::io::ErrorKind::NotFound => error,
        Err(cleanup) => error.context(format!(
            "the partial download could not be removed from {} either: {cleanup}",
            staged.display()
        )),
    }
}

/// Install a fully staged download under `local`, and make the name durable.
///
/// The rename is a directory entry, and a directory entry only survives a crash once the
/// directory does; without the second sync the caller is told a name exists that a power cut can
/// still take away.
fn install_download(staged: &Path, local: &Path) -> Result<()> {
    std::fs::rename(staged, local).with_context(|| {
        format!(
            "failed to install {} (the complete download is left at {})",
            local.display(),
            staged.display()
        )
    })?;
    crate::utils::sync_directory_of(local).with_context(|| {
        format!(
            "wrote {} but could not make its directory durable",
            local.display()
        )
    })
}

/// Where an upload stages its bytes on the guest before they take the target's name.
///
/// A sibling, so the rename that installs it stays inside one directory; a name of its own per
/// upload, so two concurrent uploads to the same target cannot install each other's half. The
/// name does not spell the target: a 250-byte name has no room left for a suffix inside the
/// guest's own limit, and the error messages name the staged path anyway.
fn staged_upload_path(remote: &GuestPath) -> Result<GuestPath> {
    static UPLOADS: AtomicU64 = AtomicU64::new(0);
    let parent = remote.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "cannot upload to {}: it has no directory to stage the bytes in",
            remote.as_str()
        )
    })?;
    parent.join(format!(
        ".qlean-upload-{}-{}.part",
        std::process::id(),
        UPLOADS.fetch_add(1, Ordering::Relaxed)
    ))
}

/// The guest's side of an upload: the four operations the staging rule needs.
///
/// A trait, not an `SftpSession`, because the whole point of the rule is what happens when one of
/// these steps fails - and a test can fail any of them without a guest. `Sftp` is the real one; the
/// tests use a fake that can refuse a write halfway, refuse the remove and refuse the rename, and
/// that also enforces the one rule the guest enforces for us: a file with an open handle cannot be
/// renamed (on Windows it cannot even be deleted).
pub(crate) trait StagedSink {
    type Writer: tokio::io::AsyncWrite + Unpin;

    /// Open `at` for writing. The staged name is ours, so this must not truncate anything.
    fn open_for_upload(
        &mut self,
        at: &str,
    ) -> impl std::future::Future<Output = Result<Self::Writer>> + Send;

    fn exists(&mut self, at: &str) -> impl std::future::Future<Output = Result<bool>> + Send;

    fn remove(&mut self, at: &str) -> impl std::future::Future<Output = Result<()>> + Send;

    fn rename(
        &mut self,
        from: &str,
        to: &str,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
}

/// Send `src`'s bytes to a staged name on the guest, then install them under `target`.
///
/// `upload_file` used to open the target with `CREATE | TRUNCATE | WRITE`, which is a truncation:
/// a cancelled or failed upload left the first half of a file under the name the caller asked for,
/// and nothing on the guest distinguished it from a complete one - a half-written
/// `deploy.json`, a truncated registry hive, a half image all still read as *some* file. The
/// download side has staged for the same reason since R203; this is the same rule on the other
/// side of the wire.
///
/// The close comes before the rename on purpose: `russh-sftp` has a `CLOSE` for every open, and
/// an open handle denies rename (and delete) on Windows, so a handle that is merely shut down but
/// not dropped would make every upload to a Windows guest fail at the last step.
///
/// Installing is not atomic: standard SFTP `rename` refuses an existing target (OpenSSH's server
/// answers `SSH_FX_FAILURE`; there is no `posix-rename` extension in `russh-sftp` 3.0.0), so an
/// overwrite has to remove the old name first. Between that remove and the rename the target is
/// absent - an accepted window, because the alternative is a half file wearing the target's name
/// for as long as nobody looks.
pub(crate) async fn install_upload<S, R>(
    sink: &mut S,
    staged: &GuestPath,
    target: &GuestPath,
    src: &mut R,
    cancel_token: &CancellationToken,
) -> Result<()>
where
    S: StagedSink,
    R: tokio::io::AsyncRead + Unpin,
{
    let mut writer = sink.open_for_upload(staged.as_str()).await?;
    let what = format!("the uploaded file {}", staged.as_str());
    let copied =
        Session::copy_stream(src, &mut writer, &what, cancel_token, "Upload cancelled").await;
    drop(writer);

    if let Err(error) = copied {
        // The half is ours, and the target still holds what it held. Removing the half must not
        // replace the failure that produced it, but a half that stays behind has to be named: it
        // is the only copy of a file nobody asked for.
        return match sink.remove(staged.as_str()).await {
            Ok(()) => Err(error),
            Err(remove) => Err(error.context(format!(
                "also failed to remove the incomplete upload at {}: {remove:#}",
                staged.as_str()
            ))),
        };
    }

    if sink.exists(target.as_str()).await? {
        sink.remove(target.as_str()).await.with_context(|| {
            format!(
                "failed to replace {} with the uploaded file (the complete upload is left at {})",
                target.as_str(),
                staged.as_str()
            )
        })?;
    }

    sink.rename(staged.as_str(), target.as_str())
        .await
        .with_context(|| {
            format!(
                "failed to install {} (the complete upload is left at {})",
                target.as_str(),
                staged.as_str()
            )
        })
}

/// The real [`StagedSink`]: an SFTP session.
pub(crate) struct SftpSink<'a>(pub(crate) &'a mut SftpSession);

impl StagedSink for SftpSink<'_> {
    type Writer = russh_sftp::client::fs::File;

    async fn open_for_upload(&mut self, at: &str) -> Result<Self::Writer> {
        // No `TRUNCATE`: the staged name is ours, and a truncate here would be the very bug this
        // path exists to avoid if the two names ever met.
        Ok(self
            .0
            .open_with_flags(at, OpenFlags::CREATE | OpenFlags::WRITE)
            .await?)
    }

    async fn exists(&mut self, at: &str) -> Result<bool> {
        Ok(self.0.try_exists(at).await?)
    }

    async fn remove(&mut self, at: &str) -> Result<()> {
        Ok(self.0.remove_file(at).await?)
    }

    async fn rename(&mut self, from: &str, to: &str) -> Result<()> {
        Ok(self.0.rename(from, to).await?)
    }
}

/// The guest-side steps a rename needs, so the decision can be tested without a guest.
///
/// The same reason [`StagedSink`] exists, one step later. Publishing a name is where the two
/// guests disagreed without anybody saying so: `Machine::rename` forwards "rename", and each
/// guest's `sshd` decided what that means when the destination already exists - the SFTP
/// specification defines the request as an error there, while OpenSSH's `sftp-server` performs
/// the system's `rename(2)`, which replaces it silently. An API that mirrors `std::fs` - where
/// `rename` *replaces* the destination - cannot leave that to the server, so Qlean decides it
/// itself (R208).
pub(crate) trait RenameSink {
    fn destination_exists(
        &mut self,
        at: &str,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;

    fn rename(
        &mut self,
        from: &str,
        to: &str,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
}

/// Move `from` onto `to`, refusing an occupied destination before anything is sent.
///
/// Three outcomes are kept apart on purpose:
/// - the destination is occupied: nothing is sent, and the error names the destination and the
///   way out (`remove_file` first), which is what a caller taking a name over has to do anyway;
/// - the probe itself fails: the rename is not sent. "I could not find out" is not "it is free" -
///   an unreadable destination treated as absent would turn a refusal into a silent replace;
/// - the destination is free: one standard rename, and the guest's own error passes through
///   unchanged (a rename the guest cannot do is the guest's answer, not Qlean's).
///
/// The probe is a separate request, so a destination that appears in between still meets the
/// server's own answer. That window cannot be closed: `russh-sftp` 3.0.0 has no `posix-rename`,
/// so no request can ask for a replacing rename that is also atomic.
pub(crate) async fn install_rename<S>(sink: &mut S, from: &str, to: &str) -> Result<()>
where
    S: RenameSink,
{
    if sink.destination_exists(to).await.with_context(|| {
        format!(
            "failed to find out whether {to} already exists, so `{from}` was not renamed: \
             guessing that the destination is free could replace it"
        )
    })? {
        bail!(
            "refusing to rename {from} to {to}: {to} already exists, and a rename does not \
             replace it. Remove {to} first if it is meant to be replaced."
        );
    }

    sink.rename(from, to).await
}

/// The real [`RenameSink`]: an SFTP session.
pub(crate) struct SftpRenameSink<'a>(pub(crate) &'a mut SftpSession);

impl RenameSink for SftpRenameSink<'_> {
    async fn destination_exists(&mut self, at: &str) -> Result<bool> {
        Ok(self.0.try_exists(at).await?)
    }

    async fn rename(&mut self, from: &str, to: &str) -> Result<()> {
        Ok(self.0.rename(from, to).await?)
    }
}

/// What one message from a command channel means to the loop waiting for a status.
#[derive(Debug, PartialEq, Eq)]
enum CommandStep {
    /// The command finished with this exit code.
    Finished(u32),
    /// The command was killed: the server sent `exit-signal` instead of a status, so there is no
    /// code to report and the reason is in the message.
    Killed(String),
    /// Anything else - output, a window adjustment, an open confirmation - leaves the loop alone.
    Output,
}

/// Decide what one channel message does to a command loop.
///
/// The decision lives here so it can be given real messages: `ChannelMsg::ExitSignal` reads
/// `signal_name`, `core_dumped` and `error_message`, and the tests hand it one of those variants
/// rather than calling [`killed_by_signal`] directly, which is what let the arm's wiring go
/// unproven when the arm first existed. Both command loops decide here, so `call` and
/// `run_command` cannot disagree about what ends a command.
fn command_step(msg: &ChannelMsg, command: &str) -> CommandStep {
    match msg {
        ChannelMsg::ExitStatus { exit_status } => CommandStep::Finished(*exit_status),
        // A killed command has no exit status: the server sends `exit-signal` instead and closes
        // the channel, so waiting for a status would report a dropped connection whenever the
        // guest killed the command.
        ChannelMsg::ExitSignal {
            signal_name,
            core_dumped,
            error_message,
            ..
        } => CommandStep::Killed(killed_by_signal(
            command,
            signal_name,
            *core_dumped,
            error_message,
        )),
        _ => CommandStep::Output,
    }
}

/// The signal an SSH `exit-signal` names, in the spelling Qlean reports.
///
/// `russh::Sig` carries the twelve names RFC 4254 section 6.10 lists plus whatever else a server
/// sent (`Custom`), and its own `name` accessor is private, so the mapping lives here. The names
/// a caller reads are the ones a shell prints and `128 + N` is computed from, not the short form
/// on the wire.
fn signal_name(signal: &russh::Sig) -> &str {
    match signal {
        russh::Sig::ABRT => "SIGABRT",
        russh::Sig::ALRM => "SIGALRM",
        russh::Sig::FPE => "SIGFPE",
        russh::Sig::HUP => "SIGHUP",
        russh::Sig::ILL => "SIGILL",
        russh::Sig::INT => "SIGINT",
        russh::Sig::KILL => "SIGKILL",
        russh::Sig::PIPE => "SIGPIPE",
        russh::Sig::QUIT => "SIGQUIT",
        russh::Sig::SEGV => "SIGSEGV",
        russh::Sig::TERM => "SIGTERM",
        russh::Sig::USR1 => "SIGUSR1",
        russh::Sig::Custom(name) => name,
    }
}

/// What a guest command that was killed by a signal reports.
///
/// A server sends `exit-signal` *instead of* `exit-status` when the command it ran died from a
/// signal (RFC 4254 section 6.10), and then closes the channel: there is no exit code to report,
/// and never was going to be one. Both command loops used to ignore the message, reach the end
/// of the channel and answer "SSH channel closed before exit status for command: ..." - the
/// same sentence a dropped connection produces. So the reason was lost twice over: a command
/// the guest killed (an OOM-killed package install, a `Stop-Computer` racing the deploy script, a
/// `kill -9` typo) read as a transport failure, and the signal that would have named it was
/// printed nowhere. The signal name and the guest's own message are reported instead.
fn killed_by_signal(
    command: &str,
    signal: &russh::Sig,
    core_dumped: bool,
    error_message: &str,
) -> String {
    let name = signal_name(signal);
    let core = if core_dumped { " and dumped core" } else { "" };
    let said = error_message.trim();
    let extra = if said.is_empty() {
        String::new()
    } else {
        format!("; the guest said: {said}")
    };
    format!(
        "the guest killed `{command}` with {name}{core}: the server sent an exit signal instead \
         of an exit status, so there is no exit code to report{extra}"
    )
}

/// Argument pair for `SFTP symlink`, in the order OpenSSH reads them.
///
/// `SSH_FXP_SYMLINK` carries two strings and the two plausible orders are both in the
/// wild: the version-3 draft names them `linkpath` then `targetpath`, while OpenSSH's
/// `sftp-server` reads the *first* string as the link's target and the second as the path
/// of the link to create (its own client sends them in that order too). `russh-sftp`
/// follows the draft: [`russh_sftp::client::SftpSession::symlink`] writes its first
/// argument into `linkpath`, so passing the link path first makes OpenSSH create the link
/// at the *target* path - silently, when that path is writable, and reported as a copy
/// failure only when it is not.
///
/// Both halves were measured, not assumed: `russh-sftp` 3.0.0 serializes
/// `Symlink { linkpath: "LINKNAME", targetpath: "TARGET" }` as `id, "LINKNAME", "TARGET"`,
/// and OpenSSH 10.6p1's `sftp-server` creates `LINKNAME -> REALFILE` from the pair
/// (`REALFILE`, `LINKNAME`) and answers `SSH_FX_FAILURE` for (`LINKNAME`, `REALFILE`).
///
/// So the pair handed to the client is `(link_target, link_path)`, in that order.
pub(crate) fn symlink_arguments(link_path: &str, link_target: &str) -> (String, String) {
    (link_target.to_string(), link_path.to_string())
}

/// Create a symbolic link in the guest, addressing the request the way OpenSSH reads it.
///
/// Callers name the link and its target, in that order, and never touch the wire order:
/// the swap lives in [`symlink_arguments`], so there is no second place to get it wrong.
pub(crate) async fn create_symlink(
    sftp: &russh_sftp::client::SftpSession,
    link_path: &str,
    link_target: &str,
) -> Result<()> {
    let (first, second) = symlink_arguments(link_path, link_target);
    sftp.symlink(first, second)
        .await
        .map(|_| ())
        .map_err(Into::into)
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
            match command_step(&msg, command) {
                CommandStep::Finished(status) => {
                    code = status;
                    channel.eof().await?;
                    break;
                }
                CommandStep::Killed(message) => bail!("{message}"),
                CommandStep::Output => match msg {
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
                    _ => {}
                },
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
            match command_step(&msg, command) {
                CommandStep::Finished(status) => {
                    code = status;
                    channel.eof().await?;
                    break;
                }
                CommandStep::Killed(message) => bail!("{message}"),
                CommandStep::Output => match msg {
                    // Write the chunk to the buffer
                    ChannelMsg::Data { ref data } => {
                        stdout.extend_from_slice(data);
                    }
                    ChannelMsg::ExtendedData { ref data, ext: 1 } => {
                        // ext == 1 means it's stderr content
                        // https://github.com/Eugeny/russh/discussions/258
                        stderr.extend_from_slice(data);
                    }
                    _ => {}
                },
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

    /// Copy `src` into `dst` to the end, and treat the flush and the close as part of the copy.
    ///
    /// Both transfers used to end with `let _ = flush(...)` and `let _ = shutdown(...)`, so a
    /// write that only failed when it was flushed - a full disk on the receiving side is the
    /// ordinary case, because `File::write` reports success while the data is still in the
    /// buffer - was reported as a successful transfer. A caller then reports an upload that
    /// never landed, or a download whose tail is missing. The close matters for the same
    /// reason: a handle that is never closed keeps the file open on the guest (on Windows an
    /// open handle denies rename and delete), and its error is the only report that the file was
    /// committed at all.
    async fn copy_stream<R, W>(
        src: &mut R,
        dst: &mut W,
        what: &str,
        cancel_token: &CancellationToken,
        cancelled: &str,
    ) -> Result<()>
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        let mut buf = vec![0u8; 128 * 1024];
        loop {
            if cancel_token.is_cancelled() {
                bail!("{cancelled}");
            }
            let n = src.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            dst.write_all(&buf[..n])
                .await
                .with_context(|| format!("failed to write {what}"))?;
        }
        dst.flush()
            .await
            .with_context(|| format!("failed to flush {what}"))?;
        dst.shutdown()
            .await
            .with_context(|| format!("failed to close {what}"))?;
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
        let staged = staged_upload_path(remote)?;
        let mut sink = SftpSink(self.get_sftp().await?);
        install_upload(&mut sink, &staged, remote, &mut src, &cancel_token).await
    }

    /// Upload `contents` as the whole of `remote`, staging it on the guest first.
    pub(crate) async fn write_file(&mut self, contents: &[u8], remote: &GuestPath) -> Result<()> {
        let staged = staged_upload_path(remote)?;
        let mut source = contents;
        let cancel_token = CancellationToken::new();
        let mut sink = SftpSink(self.get_sftp().await?);
        install_upload(&mut sink, &staged, remote, &mut source, &cancel_token).await
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

        Self::place_download(
            &mut src,
            local,
            &cancel_token,
            &format!("the downloaded copy of {}", local.display()),
        )
        .await
    }

    /// Copy `src` into `local`, letting the bytes take that name only once all of them are there.
    ///
    /// `download_file` used to `File::create(local)` first, which is a truncation: a cancelled or
    /// failed transfer left the first half of a file under the name the caller asked for, and
    /// nothing distinguished it from a complete download - a truncated registry hive or disk image
    /// reads as *some* file. Every other file Qlean writes by name ([`crate::utils::write_owner_only_atomically`])
    /// stages and renames for exactly this reason; a download is where it matters most, because the
    /// bytes cross a network.
    ///
    /// So the bytes go to a hidden sibling first, are flushed to the disk, and are renamed into
    /// place only after the last of them arrived. A failure removes the staged file and reports
    /// the error; the previous file at `local` (or its absence) is left exactly as it was.
    pub(crate) async fn place_download<R>(
        src: &mut R,
        local: &Path,
        cancel_token: &CancellationToken,
        what: &str,
    ) -> Result<()>
    where
        R: tokio::io::AsyncRead + Unpin,
    {
        let staged = staged_download_path(local);
        let mut dst = tokio::fs::File::create(&staged).await.with_context(|| {
            format!(
                "failed to create the staged download {} (the file {} is left as it was)",
                staged.display(),
                local.display()
            )
        })?;
        let mut outcome =
            Self::copy_stream(src, &mut dst, what, cancel_token, "Download cancelled").await;
        if outcome.is_ok() {
            // The rename below publishes the name whether or not the bytes ever left the page
            // cache, so they have to reach the disk first.
            outcome = dst.sync_all().await.with_context(|| {
                format!(
                    "failed to flush the staged download {} to the disk",
                    staged.display()
                )
            });
        }
        drop(dst);
        match outcome {
            Ok(()) => install_download(&staged, local),
            Err(error) => {
                let _ = tokio::fs::remove_file(&staged).await;
                Err(error)
            }
        }
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

        // Stat the root itself, not what it points at: a walk that follows links cannot
        // tell a link from its target, and a broken link is not stat-able at all.
        let root_meta = {
            let sftp = self.get_sftp().await?;
            sftp.symlink_metadata(root.as_str()).await?
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
                        // A skipped directory means `download` reports success for a tree
                        // it did not copy, so the failure has to reach the caller.
                        bail!(
                            "Failed to read the remote directory {} while walking {}: {}",
                            dir.as_str(),
                            root.as_str(),
                            e
                        );
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
                    match sftp.symlink_metadata(child_path.as_str()).await {
                        Ok(a) => a,
                        Err(e) => {
                            // An entry that cannot be stat'ed is either a broken symlink or
                            // one this walk cannot classify; either way the copy would be
                            // incomplete, so name it instead of dropping it.
                            bail!(
                                "Failed to stat {} while walking {}: {}",
                                child_path.as_str(),
                                root.as_str(),
                                e
                            );
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
    /// The symlink request must put the link's target first, because OpenSSH reads it that way.
    ///
    /// The client serializes its first argument into the draft's `linkpath` field, so the
    /// pair has to be handed over already swapped. This test does not trust the helper: it
    /// builds the same `Symlink` request the client builds and reads the wire bytes back,
    /// which is the only place the order is observable. Getting it wrong creates the link at
    /// the target's path instead of the link's own path - a silent wrong result when that
    /// path is writable, and a misleading "failed to recreate the symbolic link" otherwise
    /// (measured against OpenSSH 10.6p1's `sftp-server`).
    #[test]
    fn the_symlink_request_sends_the_link_target_before_the_link_path() {
        let (first, second) = symlink_arguments("/home/qlean/app/bin/tool", "../lib/tool");
        let request = russh_sftp::protocol::Symlink {
            id: 1,
            linkpath: first,
            targetpath: second,
        };
        let bytes = russh_sftp::ser::to_bytes(&request).expect("a symlink request serializes");

        // Payload: request id, then the two strings, each length-prefixed.
        let mut at = 4;
        let take_string = |at: &mut usize| {
            let len = u32::from_be_bytes(bytes[*at..*at + 4].try_into().unwrap()) as usize;
            let value = String::from_utf8(bytes[*at + 4..*at + 4 + len].to_vec()).unwrap();
            *at += 4 + len;
            value
        };
        let first_on_the_wire = take_string(&mut at);
        let second_on_the_wire = take_string(&mut at);
        assert_eq!(
            (first_on_the_wire.as_str(), second_on_the_wire.as_str()),
            ("../lib/tool", "/home/qlean/app/bin/tool"),
            "OpenSSH creates the link named by the second string, so the target must come first"
        );
    }

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
}
