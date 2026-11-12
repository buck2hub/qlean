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
use tracing::{debug, info};

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

/// Resolve firmware using an injectable existence probe.
fn resolve_ovmf_with(exists: &dyn Fn(&Path) -> bool) -> Option<FirmwarePaths> {
    OVMF_CANDIDATES.iter().find_map(|(code, vars, secure)| {
        let code = Path::new(code);
        if !exists(code) {
            return None;
        }
        vars.iter()
            .map(Path::new)
            .find(|vars| exists(vars))
            .map(|vars| FirmwarePaths {
                code: code.to_path_buf(),
                vars_template: vars.to_path_buf(),
                secure_boot: *secure,
            })
    })
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
            Ok(FirmwarePaths {
                secure_boot: is_secure_boot_name(&code),
                code,
                vars_template: vars,
            })
        }
        (Some(_), None) | (None, Some(_)) => bail!(
            "{ENV_OVMF_CODE} and {ENV_OVMF_VARS} must be set together; {INSTALL_HINT}"
        ),
        (None, None) => resolve_ovmf_with(&|path| path.is_file()).ok_or_else(|| {
            anyhow::anyhow!(
                "no OVMF firmware found (looked for {} known layouts under /usr/share); {INSTALL_HINT}",
                OVMF_CANDIDATES.len()
            )
        }),
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

/// Check every host prerequisite for a Windows guest, reporting all gaps at once.
pub(crate) fn ensure_host_support() -> Result<()> {
    let mut problems: Vec<String> = Vec::new();

    if !is_kvm_available() {
        problems.push(
            "KVM acceleration is unavailable: Windows guests require KVM and never fall back to TCG"
                .to_string(),
        );
    }
    if let Err(err) = resolve_ovmf() {
        problems.push(err.to_string());
    }
    let swtpm = swtpm_program();
    if !command_available(&swtpm) {
        problems.push(format!(
            "`{}` was not found: install the `swtpm` package or set {ENV_SWTPM}",
            swtpm.display()
        ));
    }
    let iso_builder = Path::new(SEED_ISO_BUILDER);
    if !command_available(iso_builder) {
        problems.push(format!(
            "`{SEED_ISO_BUILDER}` was not found: it builds the Windows seed medium, so install the `{SEED_ISO_BUILDER}` package"
        ));
    }

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
    if dest.is_file() {
        debug!("Reusing per-VM OVMF vars image at {}", dest.display());
        return Ok(dest);
    }

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

    std::fs::copy(&firmware.vars_template, &dest).with_context(|| {
        format!(
            "failed to copy OVMF vars template {} to {}",
            firmware.vars_template.display(),
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

    /// Path of the swtpm control socket used by QEMU's TPM chardev.
    pub(crate) fn socket(&self) -> &Path {
        &self.socket
    }

    /// Stop the TPM process; safe to call more than once.
    pub(crate) async fn stop(&mut self) {
        let _ = self.child.start_kill();
        let _ = tokio::time::timeout(Duration::from_secs(5), self.child.wait()).await;
    }

    /// Stop the process from synchronous code (for example `Drop`), without waiting.
    ///
    /// `Drop` cannot await, so this only signals the child; the reaper still runs when the
    /// runtime next polls the process handle.
    pub(crate) fn stop_now(&mut self) {
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

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "qlean-firmware-{tag}-{}-{}",
            std::process::id(),
            Instant::now().elapsed().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_file(path: &Path, len: usize) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, vec![0u8; len]).unwrap();
    }

    #[test]
    fn test_resolve_ovmf_with_probe_picks_first_existing_pair() {
        let code = Path::new("/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd");
        let vars = Path::new("/usr/share/edk2/x64/OVMF_VARS.4m.fd");
        let probe = |path: &Path| path == code || path == vars;
        let resolved = resolve_ovmf_with(&probe).expect("candidate matched");
        assert_eq!(resolved.code, code);
        assert_eq!(resolved.vars_template, vars);
        assert!(resolved.secure_boot);

        // A later candidate is still found when earlier ones are missing.
        let plain_code = Path::new("/usr/share/OVMF/OVMF_CODE_4M.fd");
        let plain_vars = Path::new("/usr/share/OVMF/OVMF_VARS_4M.fd");
        let probe = |path: &Path| path == plain_code || path == plain_vars;
        let resolved = resolve_ovmf_with(&probe).expect("candidate matched");
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
        let resolved = resolve_ovmf_with(&probe).expect("secure pair matched");
        assert_eq!(resolved.vars_template, ms_vars, "the .ms template wins");
        assert!(resolved.secure_boot);

        // Without the .ms template the plain one is still usable (setup mode).
        let probe = |path: &Path| path == code || path == plain_vars;
        let resolved = resolve_ovmf_with(&probe).expect("fallback matched");
        assert_eq!(resolved.vars_template, plain_vars);
        assert!(resolved.secure_boot);
    }

    #[test]
    fn test_resolve_ovmf_with_probe_reports_nothing_found() {
        assert!(resolve_ovmf_with(&|_| false).is_none());
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

    #[test]
    fn test_explicit_gaps_error_is_actionable() {
        let swtpm_gap =
            format!("`swtpm` was not found: install the `swtpm` package or set {ENV_SWTPM}");
        let xorriso_gap = format!(
            "`{SEED_ISO_BUILDER}` was not found: it builds the Windows seed medium, so install the `{SEED_ISO_BUILDER}` package"
        );
        let gaps = [
            "KVM acceleration is unavailable: Windows guests require KVM and never fall back to TCG",
            swtpm_gap.as_str(),
            xorriso_gap.as_str(),
        ];
        let message = format!(
            "Windows guest prerequisites are missing:\n- {}",
            gaps.join("\n- ")
        );
        assert!(message.contains("never fall back to TCG"));
        assert!(message.contains("install the `swtpm` package"));
        assert!(message.contains("install the `xorriso` package"));
        assert!(INSTALL_HINT.contains("edk2-ovmf"));
        assert!(INSTALL_HINT.contains("QLEAN_OVMF_CODE"));
    }

    #[test]
    fn test_command_available_checks_absolute_paths() {
        assert!(command_available(Path::new("/bin/sh")));
        assert!(!command_available(Path::new("/definitely/not/a/binary")));
    }
}
