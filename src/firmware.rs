//! Windows guest firmware (OVMF) and virtual TPM (`swtpm`) support.
//!
//! Windows guests need UEFI firmware and a TPM 2.0 device (ADR-WIN-04). The OVMF
//! *vars* image is per-VM state: it holds boot entries and the Secure Boot variable
//! store, so it must live in the run directory and survive restarts, while the OVMF
//! *code* image is a read-only host file shared by every VM.

use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use tracing::{debug, info, warn};

use crate::is_kvm_available;

/// Override for the OVMF code image (tests and unusual distro layouts).
const ENV_OVMF_CODE: &str = "QLEAN_OVMF_CODE";
/// Override for the OVMF vars template.
const ENV_OVMF_VARS: &str = "QLEAN_OVMF_VARS";
/// Override for the `swtpm` binary.
const ENV_SWTPM: &str = "QLEAN_SWTPM";

/// Host package hint used in actionable errors.
const INSTALL_HINT: &str = "install the OVMF firmware package (`edk2-ovmf` on Arch/Fedora, `ovmf` on Debian/Ubuntu) \
     or set QLEAN_OVMF_CODE and QLEAN_OVMF_VARS";

/// OVMF firmware pair resolved on the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FirmwarePaths {
    /// Read-only pflash code image, shared by all VMs.
    pub code: PathBuf,
    /// Vars template, copied once per VM.
    pub vars_template: PathBuf,
    /// Whether the resolved code image supports Secure Boot (needs SMM + secure pflash).
    pub secure_boot: bool,
}

/// Firmware state attached to a single VM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VmFirmware {
    /// Shared read-only OVMF code image.
    pub code: PathBuf,
    /// Per-VM OVMF vars image inside the run directory.
    pub vars: PathBuf,
    /// Whether Secure Boot is enabled for this VM.
    pub secure_boot: bool,
}

/// Known (code, vars candidates, secure_boot) layouts, most specific first.
///
/// Secure Boot only counts as *enabled* when the vars image already carries the
/// Microsoft KEK/db, so the `.ms`/`.secboot` vars templates are preferred and the
/// plain template is only a fallback (that combination boots in setup mode, which
/// Windows 11 rejects).
const OVMF_CANDIDATES: &[(&str, &[&str], bool)] = &[
    // Arch: edk2-ovmf
    (
        "/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd",
        &[
            "/usr/share/edk2/x64/OVMF_VARS.4m.ms.fd",
            "/usr/share/edk2/x64/OVMF_VARS.4m.fd",
        ],
        true,
    ),
    (
        "/usr/share/edk2/x64/OVMF_CODE.4m.fd",
        &["/usr/share/edk2/x64/OVMF_VARS.4m.fd"],
        false,
    ),
    (
        "/usr/share/edk2/x64/OVMF_CODE.fd",
        &["/usr/share/edk2/x64/OVMF_VARS.fd"],
        false,
    ),
    // Debian/Ubuntu: ovmf
    (
        "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd",
        &[
            "/usr/share/OVMF/OVMF_VARS_4M.ms.fd",
            "/usr/share/OVMF/OVMF_VARS_4M.fd",
        ],
        true,
    ),
    (
        "/usr/share/OVMF/OVMF_CODE_4M.fd",
        &["/usr/share/OVMF/OVMF_VARS_4M.fd"],
        false,
    ),
    (
        "/usr/share/OVMF/OVMF_CODE.fd",
        &["/usr/share/OVMF/OVMF_VARS.fd"],
        false,
    ),
    // Fedora/RHEL: edk2-ovmf
    (
        "/usr/share/edk2/ovmf/OVMF_CODE.secboot.fd",
        &[
            "/usr/share/edk2/ovmf/OVMF_VARS.secboot.fd",
            "/usr/share/edk2/ovmf/OVMF_VARS.fd",
        ],
        true,
    ),
    (
        "/usr/share/edk2/ovmf/OVMF_CODE.fd",
        &["/usr/share/edk2/ovmf/OVMF_VARS.fd"],
        false,
    ),
];

fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Infer Secure Boot support from the firmware filename.
///
/// Secure Boot needs the `secboot` OVMF build plus SMM; a code image without that
/// marker is used as-is with Secure Boot disabled and is reported as such.
fn is_secure_boot_name(path: &Path) -> bool {
    path.file_name()
        .map(|name| {
            name.to_string_lossy()
                .to_ascii_lowercase()
                .contains("secboot")
        })
        .unwrap_or(false)
}

/// Whether an OVMF vars template already carries Microsoft's Secure Boot keys.
///
/// UEFI stores Secure Boot variables as UTF-16 strings, so an *enrolled* template
/// contains the vendor subject verbatim as UTF-16LE text. The plain templates next to
/// a `secboot` code image do not, and pairing them boots the guest in setup mode, which
/// Windows 11 refuses to install from.
fn vars_template_enrolls_microsoft_keys(template: &Path) -> std::io::Result<bool> {
    const NEEDLE: &str = "Microsoft Corporation";
    let bytes = std::fs::read(template)?;
    let needle: Vec<u8> = NEEDLE.bytes().flat_map(|byte| [byte, 0x00]).collect();
    Ok(bytes.windows(needle.len()).any(|window| window == needle))
}

/// Refuse a Secure Boot firmware/vars pairing that would boot in setup mode.
///
/// This is the one firmware mistake that only shows up deep inside a Windows install,
/// as an unsupported-configuration error with no hint about the firmware, so it is
/// rejected while the resolver still knows which files the user pointed at.
fn ensure_secure_boot_pair(code: &Path, vars_template: &Path, secure_boot: bool) -> Result<()> {
    if !secure_boot {
        return Ok(());
    }
    match vars_template_enrolls_microsoft_keys(vars_template) {
        Ok(true) => Ok(()),
        Ok(false) => bail!(
            "Secure Boot firmware {} is paired with the vars template {}, which carries no \
             Microsoft Secure Boot keys: the guest would boot in setup mode and Windows 11 \
             refuses to install from it.\n\
             Point {ENV_OVMF_VARS} at the enrolled template that ships with the same package \
             (for example OVMF_VARS.4m.ms.fd next to OVMF_CODE.secboot.4m.fd), or pair a code \
             image without `secboot` and disable Secure Boot.",
            code.display(),
            vars_template.display()
        ),
        Err(error) => bail!(
            "could not read the OVMF vars template {} to confirm its Secure Boot keys: {error}",
            vars_template.display()
        ),
    }
}

/// What firmware resolution found, and why the rest was rejected.
#[derive(Debug, Default)]
struct ResolvedFirmware {
    /// The first pair that is present *and* usable.
    paths: Option<FirmwarePaths>,
    /// One sentence per present-but-unusable pair, in candidate order.
    skipped: Vec<String>,
}

/// Resolve firmware using injectable probes for presence and Secure Boot enrollment.
///
/// A candidate whose code image is present but whose vars template carries no Microsoft
/// keys is *skipped*, not returned: returning it makes the caller fail even when a plain
/// (Secure Boot disabled) candidate is available, which is the common layout on a host
/// whose distro ships only `OVMF_VARS.4m.fd` next to `OVMF_CODE.secboot.4m.fd`.
fn resolve_ovmf_with(
    exists: &dyn Fn(&Path) -> bool,
    enrolls_microsoft_keys: &dyn Fn(&Path) -> std::io::Result<bool>,
) -> ResolvedFirmware {
    let mut resolved = ResolvedFirmware::default();
    for (code, vars, secure) in OVMF_CANDIDATES {
        let code = Path::new(code);
        if !exists(code) {
            continue;
        }
        let Some(vars) = vars.iter().map(Path::new).find(|vars| exists(vars)) else {
            continue;
        };
        if *secure {
            let enrolled = match enrolls_microsoft_keys(vars) {
                Ok(true) => true,
                Ok(false) => false,
                Err(error) => {
                    // Unreadable template: treat it like a missing enrollment and keep
                    // looking, but say so instead of hiding the I/O problem.
                    resolved.skipped.push(format!(
                        "skipped {} with {}: the vars template could not be read ({error})",
                        code.display(),
                        vars.display()
                    ));
                    continue;
                }
            };
            if !enrolled {
                resolved.skipped.push(format!(
                    "skipped Secure Boot pair {} with {}: the vars template carries no \
                     Microsoft Secure Boot keys, so the guest would boot in setup mode",
                    code.display(),
                    vars.display()
                ));
                continue;
            }
        }
        resolved.paths = Some(FirmwarePaths {
            code: code.to_path_buf(),
            vars_template: vars.to_path_buf(),
            secure_boot: *secure,
        });
        break;
    }
    resolved
}

/// Report why every present candidate was skipped, when none is usable.
fn no_usable_firmware_message(resolved: &ResolvedFirmware) -> String {
    let mut message = format!(
        "no usable OVMF firmware found (looked for {} known layouts under /usr/share); {INSTALL_HINT}",
        OVMF_CANDIDATES.len()
    );
    for reason in &resolved.skipped {
        message.push_str("\n- ");
        message.push_str(reason);
    }
    if !resolved.skipped.is_empty() {
        message.push_str(&format!(
            "\nSet {ENV_OVMF_CODE} and {ENV_OVMF_VARS} to the pair you want, or pair a code image \
             without `secboot` to run with Secure Boot disabled."
        ));
    }
    message
}

/// Resolve the host OVMF firmware pair, honoring the environment overrides.
pub(crate) fn resolve_ovmf() -> Result<FirmwarePaths> {
    let env_code = env_nonempty(ENV_OVMF_CODE);
    let env_vars = env_nonempty(ENV_OVMF_VARS);
    match (env_code, env_vars) {
        (Some(code), Some(vars)) => {
            let code = PathBuf::from(code);
            let vars = PathBuf::from(vars);
            anyhow::ensure!(
                code.is_file(),
                "{ENV_OVMF_CODE} points at {}, which is not a file",
                code.display()
            );
            anyhow::ensure!(
                vars.is_file(),
                "{ENV_OVMF_VARS} points at {}, which is not a file",
                vars.display()
            );
            let secure_boot = is_secure_boot_name(&code);
            ensure_secure_boot_pair(&code, &vars, secure_boot)?;
            Ok(FirmwarePaths {
                secure_boot,
                code,
                vars_template: vars,
            })
        }
        (Some(_), None) | (None, Some(_)) => {
            bail!("{ENV_OVMF_CODE} and {ENV_OVMF_VARS} must be set together; {INSTALL_HINT}")
        }
        (None, None) => {
            let resolved = resolve_ovmf_with(&|path| path.is_file(), &|path| {
                vars_template_enrolls_microsoft_keys(path)
            });
            match resolved.paths {
                Some(paths) => {
                    // Re-check through the shared entry point: it also reports a template
                    // that cannot be read, which the probe above turned into "skipped".
                    ensure_secure_boot_pair(&paths.code, &paths.vars_template, paths.secure_boot)?;
                    Ok(paths)
                }
                None => Err(anyhow::anyhow!(no_usable_firmware_message(&resolved))),
            }
        }
    }
}

/// Program that builds the Windows seed ISO medium.
const SEED_ISO_BUILDER: &str = "xorriso";

/// Program used to run the software TPM.
fn swtpm_program() -> PathBuf {
    env_nonempty(ENV_SWTPM)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("swtpm"))
}

fn command_available(program: &Path) -> bool {
    if program.components().count() > 1 {
        return program.is_file();
    }
    let Some(paths) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&paths).any(|dir| {
        let candidate = dir.join(program);
        candidate.is_file()
    })
}

/// Collect every missing Windows host prerequisite, in one pass.
///
/// Taking the probe results as arguments keeps the aggregation testable: a user whose
/// host lacks several pieces must learn about all of them from one run instead of
/// reinstalling one package per attempt.
fn host_support_problems(
    kvm_available: bool,
    ovmf: Result<FirmwarePaths>,
    swtpm: &Path,
    swtpm_available: bool,
    seed_iso_builder_available: bool,
) -> Vec<String> {
    let mut problems: Vec<String> = Vec::new();

    if !kvm_available {
        problems.push(
            "KVM acceleration is unavailable: Windows guests require KVM and never fall back to TCG"
                .to_string(),
        );
    }
    if let Err(err) = ovmf {
        problems.push(err.to_string());
    }
    if !swtpm_available {
        problems.push(format!(
            "`{}` was not found: install the `swtpm` package or set {ENV_SWTPM}",
            swtpm.display()
        ));
    }
    if !seed_iso_builder_available {
        problems.push(format!(
            "`{SEED_ISO_BUILDER}` was not found: it builds the Windows seed medium, so install the `{SEED_ISO_BUILDER}` package"
        ));
    }

    problems
}

/// Check every host prerequisite for a Windows guest, reporting all gaps at once.
pub(crate) fn ensure_host_support() -> Result<()> {
    let swtpm = swtpm_program();
    let problems = host_support_problems(
        is_kvm_available(),
        resolve_ovmf(),
        &swtpm,
        command_available(&swtpm),
        command_available(Path::new(SEED_ISO_BUILDER)),
    );

    anyhow::ensure!(
        problems.is_empty(),
        "Windows guest prerequisites are missing:\n- {}",
        problems.join("\n- ")
    );
    Ok(())
}

/// Prepare the per-VM OVMF vars image, copying the template on first boot.
///
/// An existing vars image is kept untouched: it carries the boot entries and the
/// Secure Boot variable store that must survive shutdown/spawn cycles.
pub(crate) fn prepare_vars(run_dir: &Path, firmware: &FirmwarePaths) -> Result<PathBuf> {
    let dest = run_dir.join("ovmf_vars.fd");
    let code_len = std::fs::metadata(&firmware.code)
        .with_context(|| format!("failed to stat OVMF code image {}", firmware.code.display()))?
        .len();
    let vars_len = std::fs::metadata(&firmware.vars_template)
        .with_context(|| {
            format!(
                "failed to stat OVMF vars template {}",
                firmware.vars_template.display()
            )
        })?
        .len();
    // The two pflash files are mapped independently, so their sizes do not have to
    // match: every stock pair (Debian/Ubuntu/Fedora/Arch) ships a vars template that
    // is much smaller than the code image. Only a vars template *larger* than the code
    // image means the pair is mixed up, which is worth failing on.
    anyhow::ensure!(
        vars_len <= code_len,
        "OVMF vars template {} is {} bytes but the code image {} is only {} bytes: \
         the firmware pair looks mixed up; {INSTALL_HINT}",
        firmware.vars_template.display(),
        vars_len,
        firmware.code.display(),
        code_len
    );
    if vars_len != code_len {
        debug!(
            "OVMF code image is {} bytes and vars template is {} bytes; sizes differ in \
             stock firmware pairs and QEMU maps each pflash file on its own",
            code_len, vars_len
        );
    }

    if dest.is_file() {
        // The per-VM vars image survives restarts and holds the guest's NVRAM, so it is not
        // overwritten. A size that no longer matches the template means it was written by a
        // different OVMF build (the distribution upgraded the firmware) or left truncated:
        // booting on it either corrupts NVRAM or fails inside the firmware.
        let dest_len = std::fs::metadata(&dest)
            .with_context(|| {
                format!(
                    "failed to stat the per-VM OVMF vars image {}",
                    dest.display()
                )
            })?
            .len();
        anyhow::ensure!(
            dest_len == vars_len,
            "the per-VM OVMF vars image {} is {} bytes but the vars template {} is {} bytes: \
             the firmware was replaced or the image was truncated. Delete {} to start from the \
             template (this discards the guest's Secure Boot and TPM NVRAM) and boot again",
            dest.display(),
            dest_len,
            firmware.vars_template.display(),
            vars_len,
            dest.display()
        );
        // `std::fs::copy` reproduced the template's mode when this image was created, so a
        // read-only template also left a read-only pflash image behind.
        crate::utils::restrict_file(&dest).with_context(|| {
            format!(
                "failed to make the per-VM OVMF vars image {} writable",
                dest.display()
            )
        })?;
        debug!("Reusing per-VM OVMF vars image at {}", dest.display());
        return Ok(dest);
    }

    std::fs::copy(&firmware.vars_template, &dest).with_context(|| {
        format!(
            "failed to copy OVMF vars template {} to {}",
            firmware.vars_template.display(),
            dest.display()
        )
    })?;
    // Match the template's mode, not the template's permissions: QEMU must be able to write
    // the variables back, and the file is firmware state.
    crate::utils::restrict_file(&dest).with_context(|| {
        format!(
            "failed to restrict the per-VM OVMF vars image {} to 0600",
            dest.display()
        )
    })?;
    info!("🛡️  Prepared per-VM OVMF vars image at {}", dest.display());
    Ok(dest)
}

/// Arguments for the per-VM `swtpm` TPM 2.0 emulator.
///
/// `--ctrl` carries the socket QEMU's TPM chardev connects to, so it is created
/// owner-only even when the run directory itself is world-readable. `startup-clear`
/// matches a physical TPM, which also discards volatile state on every power cycle,
/// while sealed and NV data persist in the state directory.
fn swtpm_args(state_dir: &Path, socket: &Path, log: &Path) -> Vec<String> {
    vec![
        "socket".to_string(),
        "--tpm2".to_string(),
        "--tpmstate".to_string(),
        format!("dir={}", state_dir.to_string_lossy()),
        "--ctrl".to_string(),
        format!("type=unixio,path={},mode=0600", socket.to_string_lossy()),
        "--flags".to_string(),
        "not-need-init,startup-clear".to_string(),
        "--log".to_string(),
        format!("file={},level=1", log.to_string_lossy()),
    ]
}

/// How long `swtpm` gets to flush its state before it is killed.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

/// Ask a child process to terminate, so it can flush its state first.
///
/// `Child::start_kill` only sends `SIGKILL`, which gives `swtpm` no chance to write the TPM
/// state file. Non-Unix hosts keep the old behaviour (they cannot run a Windows guest).
fn signal_terminate(child: &mut tokio::process::Child) {
    #[cfg(unix)]
    {
        if let Some(pid) = child.id() {
            // SAFETY: `kill` with a positive pid only delivers a signal; it does not touch
            // memory, and the pid belongs to the child this handle owns.
            let sent = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
            if sent == 0 {
                return;
            }
            debug!(
                "failed to send SIGTERM to pid {pid}: {}",
                std::io::Error::last_os_error()
            );
        }
    }
    let _ = child.start_kill();
}

/// A running `swtpm` process backing one VM's TPM 2.0 device.
pub(crate) struct Swtpm {
    child: tokio::process::Child,
    socket: PathBuf,
}

impl Swtpm {
    /// Start `swtpm` for the VM in `run_dir` and wait until its control socket exists.
    pub(crate) async fn start(run_dir: &Path) -> Result<Self> {
        let state_dir = run_dir.join("tpm");
        tokio::fs::create_dir_all(&state_dir)
            .await
            .with_context(|| format!("failed to create TPM state dir {}", state_dir.display()))?;
        // The TPM state is per-VM secret material: keep it owner-only.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700))
                .await
                .with_context(|| {
                    format!(
                        "failed to restrict TPM state dir permissions on {}",
                        state_dir.display()
                    )
                })?;
        }
        let socket = run_dir.join("swtpm.sock");
        if socket.exists() {
            let _ = std::fs::remove_file(&socket);
        }
        let log = run_dir.join("swtpm.log");

        let program = swtpm_program();
        let mut cmd = tokio::process::Command::new(&program);
        cmd.args(swtpm_args(&state_dir, &socket, &log))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = cmd.spawn().with_context(|| {
            format!(
                "failed to start `{}` for the Windows guest TPM; install the `swtpm` package or set {ENV_SWTPM}",
                program.display()
            )
        })?;

        let started = Instant::now();
        loop {
            if socket.exists() {
                debug!("swtpm control socket ready at {}", socket.display());
                return Ok(Self { child, socket });
            }
            if let Some(status) = child.try_wait()? {
                let mut stderr = String::new();
                if let Some(mut err) = child.stderr.take() {
                    use tokio::io::AsyncReadExt;
                    let _ = err.read_to_string(&mut stderr).await;
                }
                bail!(
                    "`{}` exited during startup ({status}): {}",
                    program.display(),
                    stderr.trim()
                );
            }
            if started.elapsed() > Duration::from_secs(10) {
                let _ = child.start_kill();
                bail!(
                    "timed out waiting for the swtpm control socket at {}",
                    socket.display()
                );
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Wrap an arbitrary child process, so the shutdown ladder can be tested without
    /// `swtpm` installed.
    #[cfg(test)]
    pub(crate) fn from_child(child: tokio::process::Child, socket: PathBuf) -> Self {
        Self { child, socket }
    }

    /// Path of the swtpm control socket used by QEMU's TPM chardev.
    pub(crate) fn socket(&self) -> &Path {
        &self.socket
    }

    /// Stop the TPM process; safe to call more than once.
    ///
    /// `swtpm` writes its state to disk while shutting down, so a `SIGKILL` can leave a
    /// half-written state file behind and the guest then loses the TPM identity it sealed
    /// secrets against (on Windows: BitLocker recovery). Ask it to terminate, wait, and only
    /// kill if it does not.
    pub(crate) async fn stop(&mut self) {
        signal_terminate(&mut self.child);
        if tokio::time::timeout(SHUTDOWN_GRACE, self.child.wait())
            .await
            .is_err()
        {
            warn!("swtpm did not exit within {SHUTDOWN_GRACE:?}; killing it");
            let _ = self.child.start_kill();
            let _ = tokio::time::timeout(Duration::from_secs(5), self.child.wait()).await;
        }
    }

    /// Stop the process from synchronous code (for example `Drop`).
    ///
    /// `Drop` cannot await, so this signals the child, waits synchronously for a bounded
    /// time and then kills it. The wait matters: dropping a child configured with
    /// `kill_on_drop` would `SIGKILL` it immediately after the signal.
    pub(crate) fn stop_now(&mut self) {
        signal_terminate(&mut self.child);
        let started = Instant::now();
        while started.elapsed() < SHUTDOWN_GRACE {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => std::thread::sleep(Duration::from_millis(20)),
                Err(error) => {
                    warn!("failed to wait for swtpm: {error}");
                    break;
                }
            }
        }
        let _ = self.child.start_kill();
    }
}

impl Drop for Swtpm {
    fn drop(&mut self) {
        // Never leak a swtpm process if shutdown was not reached.
        let _ = self.child.start_kill();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Per-call counter for [`temp_dir`].
    ///
    /// The old name used `Instant::now().elapsed().as_nanos()`, which is measured from an
    /// instant created immediately before it and is therefore always a few nanoseconds:
    /// the "unique" suffix was effectively a constant, so two tests that asked for the
    /// same tag could hand each other stale files (a leftover read-only vars template,
    /// for example, makes the copy assertions meaningless). A counter is actually unique.
    static TEMP_DIR_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "qlean-firmware-{tag}-{}-{}",
            std::process::id(),
            TEMP_DIR_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_temp_dir_names_are_unique_within_a_run() {
        let first = temp_dir("uniqueness");
        let second = temp_dir("uniqueness");
        assert_ne!(
            first, second,
            "two test directories with the same tag must not collide"
        );
        assert!(first.is_dir() && second.is_dir());
        let _ = std::fs::remove_dir_all(&first);
        let _ = std::fs::remove_dir_all(&second);
    }

    fn write_file(path: &Path, len: usize) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, vec![0u8; len]).unwrap();
    }

    fn write_utf16(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let bytes: Vec<u8> = text.bytes().flat_map(|byte| [byte, 0x00]).collect();
        std::fs::write(path, bytes).unwrap();
    }

    #[test]
    fn test_secure_boot_pair_rejects_a_template_without_microsoft_keys() {
        let root = temp_dir("secboot-pair");
        let code = root.join("OVMF_CODE.secboot.4m.fd");
        write_file(&code, 4096);
        let plain = root.join("OVMF_VARS.4m.fd");
        write_file(&plain, 1024);
        let enrolled = root.join("OVMF_VARS.4m.ms.fd");
        write_utf16(&enrolled, "Microsoft Corporation");

        assert!(!vars_template_enrolls_microsoft_keys(&plain).unwrap());
        assert!(vars_template_enrolls_microsoft_keys(&enrolled).unwrap());

        let error = ensure_secure_boot_pair(&code, &plain, true)
            .expect_err("a setup-mode pairing must be refused")
            .to_string();
        assert!(error.contains("setup mode"), "{error}");
        assert!(error.contains("QLEAN_OVMF_VARS"), "{error}");
        assert!(error.contains("OVMF_VARS.4m.ms.fd"), "{error}");

        ensure_secure_boot_pair(&code, &enrolled, true).expect("enrolled template is accepted");
        // Without Secure Boot the template contents do not matter.
        ensure_secure_boot_pair(&code, &plain, false).expect("no Secure Boot, no key check");
    }

    /// Enrollment probe for the resolver tests: only templates named `*.ms.fd` count.
    fn ms_only(path: &Path) -> std::io::Result<bool> {
        Ok(path
            .file_name()
            .map(|name| name.to_string_lossy().ends_with(".ms.fd"))
            .unwrap_or(false))
    }

    #[test]
    fn test_resolve_ovmf_with_probe_picks_first_existing_pair() {
        let code = Path::new("/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd");
        let vars = Path::new("/usr/share/edk2/x64/OVMF_VARS.4m.ms.fd");
        let probe = |path: &Path| path == code || path == vars;
        let resolved = resolve_ovmf_with(&probe, &ms_only)
            .paths
            .expect("candidate");
        assert_eq!(resolved.code, code);
        assert_eq!(resolved.vars_template, vars);
        assert!(resolved.secure_boot);

        // A later candidate is still found when earlier ones are missing.
        let plain_code = Path::new("/usr/share/OVMF/OVMF_CODE_4M.fd");
        let plain_vars = Path::new("/usr/share/OVMF/OVMF_VARS_4M.fd");
        let probe = |path: &Path| path == plain_code || path == plain_vars;
        let resolved = resolve_ovmf_with(&probe, &ms_only)
            .paths
            .expect("candidate");
        assert_eq!(resolved.code, plain_code);
        assert!(!resolved.secure_boot);
    }

    #[test]
    fn test_secure_boot_prefers_the_microsoft_vars_template() {
        // Secure Boot is only enabled with the Microsoft KEK/db enrolled; the plain
        // vars template boots in setup mode, which Windows 11 refuses.
        let code = Path::new("/usr/share/OVMF/OVMF_CODE_4M.secboot.fd");
        let ms_vars = Path::new("/usr/share/OVMF/OVMF_VARS_4M.ms.fd");
        let plain_vars = Path::new("/usr/share/OVMF/OVMF_VARS_4M.fd");
        let probe = |path: &Path| path == code || path == ms_vars || path == plain_vars;
        let resolved = resolve_ovmf_with(&probe, &ms_only)
            .paths
            .expect("secure pair");
        assert_eq!(resolved.vars_template, ms_vars, "the .ms template wins");
        assert!(resolved.secure_boot);
    }

    #[test]
    fn test_a_secboot_pair_without_keys_does_not_hide_a_plain_candidate() {
        // The layout that broke: the distro ships `OVMF_CODE.secboot.4m.fd` next to the
        // *plain* vars template, and also a usable non-Secure-Boot code image. Refusing
        // the pair must fall through to the plain candidate instead of failing the host.
        let secboot_code = Path::new("/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd");
        let plain_vars = Path::new("/usr/share/edk2/x64/OVMF_VARS.4m.fd");
        let plain_code = Path::new("/usr/share/edk2/x64/OVMF_CODE.4m.fd");
        let probe = |path: &Path| path == secboot_code || path == plain_vars || path == plain_code;

        let resolved = resolve_ovmf_with(&probe, &ms_only);
        let paths = resolved.paths.expect("the plain candidate is usable");
        assert_eq!(paths.code, plain_code);
        assert_eq!(paths.vars_template, plain_vars);
        assert!(!paths.secure_boot, "Secure Boot must be disabled here");
        assert_eq!(resolved.skipped.len(), 1, "{:?}", resolved.skipped);
        assert!(
            resolved.skipped[0].contains("setup mode"),
            "{:?}",
            resolved.skipped
        );
    }

    #[test]
    fn test_no_usable_firmware_explains_every_skipped_pair() {
        // Only the unusable pair exists: the error has to say why, and how to override.
        let secboot_code = Path::new("/usr/share/edk2/ovmf/OVMF_CODE.secboot.fd");
        let plain_vars = Path::new("/usr/share/edk2/ovmf/OVMF_VARS.fd");
        let probe = |path: &Path| path == secboot_code || path == plain_vars;

        let resolved = resolve_ovmf_with(&probe, &ms_only);
        assert!(resolved.paths.is_none());
        let message = no_usable_firmware_message(&resolved);
        assert!(message.contains("no usable OVMF firmware"), "{message}");
        assert!(message.contains("setup mode"), "{message}");
        assert!(message.contains(ENV_OVMF_CODE), "{message}");
    }

    #[test]
    fn test_an_unreadable_vars_template_is_reported_and_skipped() {
        let secboot_code = Path::new("/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd");
        let vars = Path::new("/usr/share/edk2/x64/OVMF_VARS.4m.fd");
        let probe = |path: &Path| path == secboot_code || path == vars;
        let unreadable = |_: &Path| Err(std::io::Error::other("permission denied"));

        let resolved = resolve_ovmf_with(&probe, &unreadable);
        assert!(resolved.paths.is_none());
        assert!(
            resolved.skipped[0].contains("permission denied"),
            "{:?}",
            resolved.skipped
        );
    }

    #[test]
    fn test_resolve_ovmf_with_probe_reports_nothing_found() {
        let resolved = resolve_ovmf_with(&|_| false, &ms_only);
        assert!(resolved.paths.is_none());
        assert!(resolved.skipped.is_empty());
        assert!(no_usable_firmware_message(&resolved).contains("no usable OVMF firmware"));
    }

    #[test]
    fn test_secure_boot_detected_from_filename() {
        assert!(is_secure_boot_name(Path::new(
            "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd"
        )));
        assert!(!is_secure_boot_name(Path::new(
            "/usr/share/OVMF/OVMF_CODE_4M.fd"
        )));
        assert!(!is_secure_boot_name(Path::new("/")));
    }

    #[test]
    fn test_prepare_vars_copies_template_once() {
        let root = temp_dir("vars");
        let run_dir = root.join("run");
        std::fs::create_dir_all(&run_dir).unwrap();
        let code = root.join("code.fd");
        let vars_template = root.join("vars.fd");
        write_file(&code, 64);
        write_file(&vars_template, 64);
        let firmware = FirmwarePaths {
            code: code.clone(),
            vars_template: vars_template.clone(),
            secure_boot: false,
        };

        let dest = prepare_vars(&run_dir, &firmware).unwrap();
        assert_eq!(dest, run_dir.join("ovmf_vars.fd"));
        assert_eq!(std::fs::read(&dest).unwrap().len(), 64);

        // A restart must keep the existing per-VM vars content.
        std::fs::write(&dest, vec![1u8; 64]).unwrap();
        let again = prepare_vars(&run_dir, &firmware).unwrap();
        assert_eq!(again, dest);
        assert_eq!(std::fs::read(&again).unwrap(), vec![1u8; 64]);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    #[cfg(unix)]
    fn test_prepare_vars_makes_a_read_only_template_writable() {
        use std::os::unix::fs::PermissionsExt;

        // Some distributions ship the vars template as `0444`; `std::fs::copy` reproduces
        // the source mode, which would leave QEMU unable to write the variables back.
        let root = temp_dir("vars-readonly");
        let run_dir = root.join("run");
        std::fs::create_dir_all(&run_dir).unwrap();
        let code = root.join("code.fd");
        let vars_template = root.join("vars.fd");
        write_file(&code, 64);
        write_file(&vars_template, 64);
        std::fs::set_permissions(&vars_template, std::fs::Permissions::from_mode(0o444)).unwrap();
        let firmware = FirmwarePaths {
            code,
            vars_template,
            secure_boot: false,
        };

        let dest = prepare_vars(&run_dir, &firmware).expect("a read-only template is usable");
        let mode = std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "per-VM vars must be writable and owner-only");
        // The point of 0600 here: a writable pflash image holding NVRAM and keys.
        std::fs::write(&dest, vec![2u8; 64]).expect("vars image must be writable");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_prepare_vars_rejects_a_stale_per_vm_image() {
        // The distribution replaced OVMF after this VM was created: booting on the old
        // NVRAM either corrupts it or fails inside the firmware, so say so instead.
        let root = temp_dir("vars-stale");
        let run_dir = root.join("run");
        std::fs::create_dir_all(&run_dir).unwrap();
        let code = root.join("code.fd");
        let vars_template = root.join("vars.fd");
        write_file(&code, 4096);
        write_file(&vars_template, 540);
        let dest = run_dir.join("ovmf_vars.fd");
        write_file(&dest, 256);
        let firmware = FirmwarePaths {
            code,
            vars_template,
            secure_boot: true,
        };

        let err = prepare_vars(&run_dir, &firmware).unwrap_err().to_string();
        assert!(err.contains("540") && err.contains("256"), "{err}");
        assert!(err.contains("Delete"), "must say how to recover: {err}");
        // The guest's NVRAM must not be silently replaced by the template.
        assert_eq!(std::fs::read(&dest).unwrap().len(), 256);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn test_stop_now_lets_the_child_terminate_gracefully() {
        // `sleep` exits on SIGTERM, so the synchronous shutdown must not fall through to
        // SIGKILL and must not block for the whole grace period.
        let child = tokio::process::Command::new("sleep")
            .arg("30")
            .kill_on_drop(true)
            .spawn()
            .expect("sleep is available");
        let mut swtpm = Swtpm::from_child(child, PathBuf::from("/nonexistent/swtpm.sock"));

        let started = Instant::now();
        swtpm.stop_now();
        let elapsed = started.elapsed();
        assert!(elapsed < SHUTDOWN_GRACE, "took {elapsed:?}");
        let status = swtpm.child.try_wait().expect("try_wait works");
        assert!(status.is_some(), "child must be gone after a graceful stop");
    }

    #[tokio::test]
    async fn test_stop_kills_a_child_that_ignores_sigterm() {
        // A hung `swtpm` must not hang the shutdown path: the grace period expires and the
        // process is killed.
        // The trailing loop keeps `sh` as the surviving process: a bare last command would
        // be `exec`ed and inherit the default `SIGTERM` disposition instead of the trap.
        // The marker file proves the trap is installed before the signal is sent, otherwise
        // the test would race the shell's startup and pass for the wrong reason.
        let dir = tempfile::tempdir().expect("temp dir");
        let marker = dir.path().join("trapped");
        let child = tokio::process::Command::new("sh")
            .args([
                "-c",
                &format!(
                    "trap '' TERM; : > {}; while :; do sleep 0.05; done",
                    marker.display()
                ),
            ])
            .kill_on_drop(true)
            .spawn()
            .expect("sh is available");
        let mut swtpm = Swtpm::from_child(child, PathBuf::from("/nonexistent/swtpm.sock"));
        for _ in 0..250 {
            if marker.is_file() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(marker.is_file(), "the shell must install the trap first");

        let started = Instant::now();
        tokio::time::timeout(Duration::from_secs(20), swtpm.stop())
            .await
            .expect("stop must finish");
        assert!(
            started.elapsed() >= SHUTDOWN_GRACE,
            "the grace period must expire before the child is killed"
        );
        let status = swtpm.child.try_wait().expect("try_wait works");
        assert!(
            status.is_some(),
            "child must be killed after the grace period"
        );
    }

    #[test]
    fn test_swtpm_args_keep_the_control_socket_owner_only() {
        let args = swtpm_args(
            Path::new("/run/qlean/abc/tpm"),
            Path::new("/run/qlean/abc/swtpm.sock"),
            Path::new("/run/qlean/abc/swtpm.log"),
        );
        assert_eq!(args[0], "socket");
        assert!(args.contains(&"--tpm2".to_string()), "{args:?}");
        assert!(
            args.iter()
                .any(|a| a == "type=unixio,path=/run/qlean/abc/swtpm.sock,mode=0600"),
            "{args:?}"
        );
        assert!(
            args.contains(&"not-need-init,startup-clear".to_string()),
            "{args:?}"
        );
        assert!(
            args.contains(&"dir=/run/qlean/abc/tpm".to_string()),
            "{args:?}"
        );
    }

    #[test]
    fn test_prepare_vars_accepts_a_smaller_vars_template() {
        // Stock pairs look like this: a multi-megabyte code image with a ~528 KiB
        // vars template. Rejecting that shape would block every real host.
        let root = temp_dir("small-vars");
        let run_dir = root.join("run");
        std::fs::create_dir_all(&run_dir).unwrap();
        let code = root.join("code.fd");
        let vars_template = root.join("vars.fd");
        write_file(&code, 4096);
        write_file(&vars_template, 540);
        let firmware = FirmwarePaths {
            code,
            vars_template,
            secure_boot: false,
        };

        let dest = prepare_vars(&run_dir, &firmware).expect("a smaller vars template is normal");
        assert_eq!(std::fs::read(&dest).unwrap().len(), 540);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_prepare_vars_rejects_a_vars_template_larger_than_the_code_image() {
        let root = temp_dir("mismatch");
        let run_dir = root.join("run");
        std::fs::create_dir_all(&run_dir).unwrap();
        let code = root.join("code.fd");
        let vars_template = root.join("vars.fd");
        write_file(&code, 64);
        write_file(&vars_template, 128);
        let firmware = FirmwarePaths {
            code,
            vars_template,
            secure_boot: false,
        };

        let err = prepare_vars(&run_dir, &firmware).unwrap_err().to_string();
        assert!(err.contains("pair looks mixed up"), "{err}");
        assert!(!run_dir.join("ovmf_vars.fd").exists());

        let _ = std::fs::remove_dir_all(&root);
    }

    fn firmware_fixture() -> FirmwarePaths {
        FirmwarePaths {
            code: PathBuf::from("/usr/share/OVMF/OVMF_CODE_4M.secboot.fd"),
            vars_template: PathBuf::from("/usr/share/OVMF/OVMF_VARS_4M.ms.fd"),
            secure_boot: true,
        }
    }

    #[test]
    fn test_host_support_reports_every_gap_at_once() {
        let problems = host_support_problems(
            false,
            Err(anyhow::anyhow!("no OVMF firmware found")),
            Path::new("swtpm"),
            false,
            false,
        );

        assert_eq!(problems.len(), 4, "gaps: {problems:?}");
        assert!(problems[0].contains("never fall back to TCG"));
        assert!(problems[1].contains("no OVMF firmware found"));
        assert!(problems[2].contains("install the `swtpm` package"));
        assert!(problems[2].contains(ENV_SWTPM));
        assert!(problems[3].contains("install the `xorriso` package"));

        // The aggregated error keeps every line, so one run lists all four gaps.
        let message = format!(
            "Windows guest prerequisites are missing:\n- {}",
            problems.join("\n- ")
        );
        assert_eq!(message.lines().count(), 5, "{message}");
    }

    #[test]
    fn test_host_support_is_quiet_when_everything_is_present() {
        let problems =
            host_support_problems(true, Ok(firmware_fixture()), Path::new("swtpm"), true, true);

        assert!(problems.is_empty(), "unexpected gaps: {problems:?}");
    }

    #[test]
    fn test_host_support_reports_only_the_missing_piece() {
        let problems = host_support_problems(
            true,
            Ok(firmware_fixture()),
            Path::new("/opt/swtpm"),
            true,
            false,
        );

        assert_eq!(problems.len(), 1, "gaps: {problems:?}");
        assert!(
            problems[0].contains("`xorriso` was not found"),
            "{problems:?}"
        );

        let problems = host_support_problems(
            true,
            Ok(firmware_fixture()),
            Path::new("/opt/swtpm"),
            false,
            true,
        );
        assert_eq!(problems.len(), 1, "gaps: {problems:?}");
        assert!(problems[0].contains("/opt/swtpm"), "{problems:?}");
        assert!(INSTALL_HINT.contains("edk2-ovmf"));
        assert!(INSTALL_HINT.contains("QLEAN_OVMF_CODE"));
    }

    #[test]
    fn test_command_available_checks_absolute_paths() {
        assert!(command_available(Path::new("/bin/sh")));
        assert!(!command_available(Path::new("/definitely/not/a/binary")));
    }
}
