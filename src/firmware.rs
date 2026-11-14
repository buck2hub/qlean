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

/// Notice to emit when resolution had to fall back to a non-Secure-Boot pair.
///
/// [`resolve_ovmf_with`] skipping a `secboot` pair whose vars template carries no
/// Microsoft keys is the right call: booting it would land the guest in setup mode.
/// What is *not* right is doing it silently. The most common layout on a rolling
/// distro is exactly that pair plus a usable plain one, so the guest then boots with
/// Secure Boot disabled, and a Windows 11 image refuses to install with an
/// unsupported-configuration error that says nothing about the firmware. The reason is
/// already known here, so it has to reach the user.
fn secure_boot_skipped_notice(skipped: &[String]) -> Option<String> {
    if skipped.is_empty() {
        return None;
    }
    let mut notice = String::from(
        "Secure Boot is disabled for this Windows guest: the host has no OVMF pair with \
         Microsoft's Secure Boot keys enrolled, so Qlean fell back to a code image without \
         Secure Boot. Windows 11 requires Secure Boot and refuses to install without it.",
    );
    for reason in skipped {
        notice.push_str("\n- ");
        notice.push_str(reason);
    }
    notice.push_str(&format!(
        "\nInstall the enrolled vars template that ships with the same package (for example \
         OVMF_VARS.4m.ms.fd next to OVMF_CODE.secboot.4m.fd) and set {ENV_OVMF_VARS} to it if \
         this guest is Windows 11."
    ));
    Some(notice)
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
                    // Falling back to a non-Secure-Boot pair is legitimate, but it changes
                    // what the guest sees, so it is never silent.
                    if !paths.secure_boot
                        && let Some(notice) = secure_boot_skipped_notice(&resolved.skipped)
                    {
                        warn!("{notice}");
                    }
                    Ok(paths)
                }
                None => Err(anyhow::anyhow!(no_usable_firmware_message(&resolved))),
            }
        }
    }
}

/// Program that builds the Windows seed ISO medium.
pub(crate) const SEED_ISO_BUILDER: &str = "xorriso";

/// Program that answers "which address does this MAC have on Qlean's network?".
const LEASE_TOOL: &str = "virsh";

/// Program that creates the per-VM disk overlay, run before QEMU itself.
const QEMU_IMG: &str = "qemu-img";

/// The QEMU binary a Windows guest runs under (Windows guests are amd64 only).
const QEMU_SYSTEM: &str = "qemu-system-x86_64";

/// Program used to run the software TPM.
fn swtpm_program() -> PathBuf {
    env_nonempty(ENV_SWTPM)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("swtpm"))
}

/// Whether `path` is a regular file the host can actually execute.
///
/// `is_file` alone answers "something is there", which is what the gate used to ask: a file
/// that is present but not executable (an unpacked tarball, a backup restored without its
/// mode, a mount with `noexec`) passed the check and then failed inside `launch` with a bare
/// `Permission denied (os error 13)` naming no program. The gate exists to name every gap at
/// the cheapest moment, so "there but unusable" is a gap of its own.
///
/// The definition itself lives in `crate::utils::is_executable_file`: the Linux dependency
/// gate (`check_commands_available`) asks the same question, and two answers would let one
/// gate accept exactly the file the other rejects.
fn executable_file(path: &Path) -> bool {
    crate::utils::is_executable_file(path)
}

/// Whether a host program can be run, and if not, why.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Presence {
    /// Found, and executable.
    Ready,
    /// Nothing by that name exists.
    Missing,
    /// The name resolves to a file that cannot be executed.
    NotExecutable(PathBuf),
}

/// Resolve `program` the way `Command::new` would: a bare name through `PATH`, a path as given.
fn program_presence(program: &Path) -> Presence {
    if program.components().count() > 1 {
        return if executable_file(program) {
            Presence::Ready
        } else if program.is_file() {
            Presence::NotExecutable(program.to_path_buf())
        } else {
            Presence::Missing
        };
    }
    let Some(paths) = std::env::var_os("PATH") else {
        return Presence::Missing;
    };
    let mut unusable = None;
    for dir in std::env::split_paths(&paths) {
        let candidate = dir.join(program);
        if executable_file(&candidate) {
            return Presence::Ready;
        }
        if unusable.is_none() && candidate.is_file() {
            unusable = Some(candidate);
        }
    }
    match unusable {
        Some(path) => Presence::NotExecutable(path),
        None => Presence::Missing,
    }
}

/// How a program that exists but cannot run is named, ahead of that program's remedy.
fn not_executable_prefix(program: &str, path: &Path) -> String {
    format!(
        "`{program}` was found at {} but cannot be executed, so it is not usable: fix that file's \
         permissions or reinstall the package that ships it",
        path.display()
    )
}

/// The gap one program leaves, worded so the same instruction fits both reasons.
fn program_problem(program: &str, presence: Presence, remedy: &str) -> Option<String> {
    match presence {
        Presence::Ready => None,
        Presence::Missing => Some(format!("`{program}` was not found: {remedy}")),
        Presence::NotExecutable(path) => Some(format!(
            "{}; {remedy}",
            not_executable_prefix(program, &path)
        )),
    }
}

/// Everything the Windows guest path needs from the host, probed once.
///
/// Taking the probe results as fields keeps the aggregation testable: a user whose host
/// lacks several pieces must learn about all of them from one run instead of reinstalling
/// one package per attempt.
struct HostProbes<'a> {
    qemu_img: Presence,
    qemu_system: Presence,
    kvm_available: bool,
    ovmf: Result<FirmwarePaths>,
    swtpm: &'a Path,
    swtpm_presence: Presence,
    seed_iso_builder: Presence,
    virsh: Presence,
}

/// Collect every missing Windows host prerequisite, in one pass.
///
/// The programs come first because they are what the machine hits first: `qemu-img` runs
/// before QEMU and before OVMF or the TPM are touched. Leaving them out made the "all gaps
/// at once" check useless on a bare host: the first error was an unrelated `qemu-img`
/// failure, and the missing `qemu-system-x86_64` appeared only after that was installed.
fn host_support_problems(probes: HostProbes<'_>) -> Vec<String> {
    let HostProbes {
        qemu_img,
        qemu_system,
        kvm_available,
        ovmf,
        swtpm,
        swtpm_presence,
        seed_iso_builder,
        virsh,
    } = probes;

    let mut problems: Vec<String> = Vec::new();

    // `Presence` separates "not installed" from "installed but cannot run", because the two
    // need different words: telling someone to install a package they already have sends them
    // to the wrong problem, which is exactly what a bare `Permission denied` from `launch` did.
    problems.extend(program_problem(
        QEMU_IMG,
        qemu_img,
        "it creates the per-VM disk overlay from the Windows image, so install the `qemu-img` \
         package (part of `qemu-base`)",
    ));
    problems.extend(program_problem(
        QEMU_SYSTEM,
        qemu_system,
        "it is the program the Windows guest runs under, so install the `qemu-system-x86` package",
    ));
    if !kvm_available {
        problems.push(
            "KVM acceleration is unavailable: Windows guests require KVM and never fall back to TCG"
                .to_string(),
        );
    }
    if let Err(err) = ovmf {
        problems.push(err.to_string());
    }
    problems.extend(program_problem(
        &swtpm.display().to_string(),
        swtpm_presence,
        &format!("install the `swtpm` package or set {ENV_SWTPM}"),
    ));
    problems.extend(program_problem(
        SEED_ISO_BUILDER,
        seed_iso_builder,
        "it builds the Windows seed medium, so install the `xorriso` package",
    ));
    // Built here rather than through `program_problem` for one reason: the plan quotes this
    // sentence word for word, so both of its shapes have to be plain source text that
    // `the_plan_quotes_the_prerequisite_error_the_windows_gate_prints` can read back.
    match virsh {
        Presence::Ready => {}
        Presence::Missing => problems.push(format!(
            "`{LEASE_TOOL}` was not found: a Windows guest's address comes from \
             `{LEASE_TOOL} net-dhcp-leases`, so install the `libvirt` package before starting one"
        )),
        Presence::NotExecutable(path) => problems.push(format!(
            "{}; a Windows guest's address comes from `{LEASE_TOOL} net-dhcp-leases`, so install \
             the `libvirt` package before starting one",
            not_executable_prefix(LEASE_TOOL, &path)
        )),
    }

    problems
}

/// Check every host prerequisite for a Windows guest, reporting all gaps at once.
pub(crate) fn ensure_host_support() -> Result<()> {
    let swtpm = swtpm_program();
    let problems = host_support_problems(HostProbes {
        qemu_img: program_presence(Path::new(QEMU_IMG)),
        qemu_system: program_presence(Path::new(QEMU_SYSTEM)),
        kvm_available: is_kvm_available(),
        ovmf: resolve_ovmf(),
        swtpm_presence: program_presence(&swtpm),
        seed_iso_builder: program_presence(Path::new(SEED_ISO_BUILDER)),
        virsh: program_presence(Path::new(LEASE_TOOL)),
        swtpm: &swtpm,
    });

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
/// What sits at the vars image path when it is not a regular file, for the message.
///
/// A link is named by its target, because "a symlink to /usr/share/OVMF/OVMF_VARS.fd" is what a
/// reader needs to recognise the hand-edit; anything else is described by its kind.
fn not_a_plain_file(path: &Path, meta: &std::fs::Metadata) -> String {
    let kind = meta.file_type();
    if kind.is_symlink() {
        return match std::fs::read_link(path) {
            Ok(target) => format!("a symlink to {}", target.display()),
            Err(_) => "a symlink".to_string(),
        };
    }
    if kind.is_dir() {
        return "a directory".to_string();
    }
    "not a regular file".to_string()
}

/// What sits at the `swtpm` control socket path.
///
/// [`Swtpm::start`] used `path.exists()` as its readiness answer, and "exists" is not
/// "listening": a directory or a plain file left in the run directory answered yes on the
/// first poll, so `start` returned a TPM whose control socket was not a socket and the launch
/// carried on to hand QEMU `-chardev socket,path=<that entry>`. Measured against a real
/// `swtpm` 0.10.2: with a directory at the path, `start` returned `Ok` in 0.02s and the
/// caller was told the TPM was ready while nothing had bound the endpoint.
///
/// A socket is the one shape that can be ready; a leftover socket file (a crashed run) is
/// removed so the new `swtpm` can bind; anything else is refused by name instead of being
/// deleted, because the run directory is the user's and Qlean did not create that entry.
#[derive(Debug, PartialEq, Eq)]
enum ControlSocket {
    /// Nothing there: `swtpm` creates the socket when it is ready.
    Absent,
    /// A unix socket: the endpoint, or the stale one a crashed run left behind.
    Socket,
    /// Something else, worded for the message that refuses it.
    Foreign(String),
}

impl ControlSocket {
    /// Whether the TPM's control socket is actually there.
    fn is_socket(&self) -> bool {
        matches!(self, ControlSocket::Socket)
    }
}

/// Classify the entry at the `swtpm` control socket path.
fn control_socket_state(path: &Path) -> std::io::Result<ControlSocket> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ControlSocket::Absent);
        }
        Err(error) => return Err(error),
    };
    if is_socket_entry(&meta) {
        return Ok(ControlSocket::Socket);
    }
    Ok(ControlSocket::Foreign(describe_control_socket_entry(
        path, &meta,
    )))
}

/// Whether this directory entry really is a unix socket.
///
/// The control socket is a unix socket, so only a Unix host can tell one from a file. On a
/// host that cannot: `swtpm` does not run there either - a Windows guest needs KVM - so the
/// answer only has to stay out of the way: anything that exists keeps the previous meaning
/// instead of turning every start into a refusal.
#[cfg(unix)]
fn is_socket_entry(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::FileTypeExt;
    meta.file_type().is_socket()
}

#[cfg(not(unix))]
fn is_socket_entry(_meta: &std::fs::Metadata) -> bool {
    true
}

/// Name the entry that is not a socket, for the refusal message.
///
/// This sentence is everything the user has before deciding what to delete, so it has to name
/// what is really there. A FIFO or a device node used to be reported as "a regular file" - the
/// one property the message exists to report was the one it got wrong, and a reader who ran
/// `ls -l` on the path was told to distrust the refusal instead of the entry.
fn describe_control_socket_entry(path: &Path, meta: &std::fs::Metadata) -> String {
    let file_type = meta.file_type();
    if file_type.is_symlink() {
        return match std::fs::read_link(path) {
            Ok(target) => format!("a symlink to {}", target.display()),
            Err(_) => "a symlink".to_string(),
        };
    }
    if file_type.is_dir() {
        return "a directory".to_string();
    }
    match special_file_kind(&file_type) {
        Some(kind) => kind.to_string(),
        None => "a regular file".to_string(),
    }
}

/// The entry kinds that are neither a regular file nor a directory, on a host that has them.
#[cfg(unix)]
fn special_file_kind(file_type: &std::fs::FileType) -> Option<&'static str> {
    use std::os::unix::fs::FileTypeExt;
    if file_type.is_fifo() {
        Some("a FIFO (named pipe)")
    } else if file_type.is_char_device() {
        Some("a character device")
    } else if file_type.is_block_device() {
        Some("a block device")
    } else {
        None
    }
}

#[cfg(not(unix))]
fn special_file_kind(_file_type: &std::fs::FileType) -> Option<&'static str> {
    None
}

/// Whether a `/proc/<pid>/cmdline` payload is a `swtpm` serving `state_dir`.
///
/// `swtpm` does not lock the directory it keeps the TPM state in. Measured in the container
/// against `swtpm` 0.10.2: two daemons started with the same `--tpmstate dir=` both stayed
/// alive, both bound their own control socket, and both wrote the same `tpm2-00.permall`.
/// So "there is already a `swtpm` for this VM" is invisible in the state directory itself and
/// has to be read off the process table, exactly like [`cmdline_is_this_machines_qemu`] reads
/// QEMU's identity off it: a leftover socket file and a socket a *live* daemon is serving look
/// identical, and only the process tells them apart.
///
/// Only `argv[0]` names the program: a later argument can name `swtpm` (a log path, a
/// comment) without the process being one. The state directory is then matched on the
/// argument that *follows* `--tpmstate` and on its first comma-separated field, because the
/// value is an option list (`dir=<path>,mode=0600`) and a prefix comparison would confuse
/// `.../tpm` with `.../tpm2`.
///
/// [`cmdline_is_this_machines_qemu`]: crate::machine::cmdline_is_this_machines_qemu
fn cmdline_is_swtpm_for(cmdline: &[u8], state_dir: &Path) -> bool {
    let mut arguments = cmdline.split(|byte| *byte == 0);
    let program = String::from_utf8_lossy(arguments.next().unwrap_or_default());
    let program = program.rsplit('/').next().unwrap_or_default();
    if !program.starts_with("swtpm") {
        return false;
    }
    let wanted = state_dir.to_string_lossy();
    let mut previous = String::new();
    for argument in arguments {
        let argument = String::from_utf8_lossy(argument);
        if previous == "--tpmstate" {
            let value = argument.split(',').next().unwrap_or_default();
            if value == format!("dir={wanted}") {
                return true;
            }
        }
        previous = argument.to_string();
    }
    false
}

/// The pid of a `swtpm` that is already serving `state_dir`, if any.
///
/// A process table that cannot be read yields `None`: refusing a start requires an owner that
/// was actually found, and guessing one would make the TPM unavailable for no reason.
fn live_swtpm_on(state_dir: &Path) -> std::io::Result<Option<u32>> {
    swtpm_in(Path::new("/proc"), state_dir)
}

/// Find a `swtpm` serving `state_dir`, reading a directory shaped like `/proc`.
///
/// `Ok(None)` is the answer "the process table was read, and no `swtpm` serves this state
/// directory" - the only answer that licenses [`Swtpm::start`] to remove an existing socket.
/// Every way of *failing to look* is an `Err`, because the two used to be one answer:
/// `read_dir("/proc")` was passed through `.ok()?` and every unreadable `cmdline` was skipped,
/// so a host whose `/proc` a process cannot enumerate (`hidepid=2`, a chroot without `/proc`,
/// a sandbox) looked exactly like a host with no daemon - and `start` then deleted the socket
/// of the daemon it could not see and started a second one on the same state file.
///
/// The table is handed in as a path so the shapes a real host cannot be asked for (an
/// unreadable table, a `cmdline` that exists but cannot be read) can be tested directly.
fn swtpm_in(proc_root: &Path, state_dir: &Path) -> std::io::Result<Option<u32>> {
    let entries = std::fs::read_dir(proc_root)?;
    for entry in entries {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        match std::fs::read(entry.path().join("cmdline")) {
            Ok(cmdline) => {
                if cmdline_is_swtpm_for(&cmdline, state_dir) {
                    return Ok(Some(pid));
                }
            }
            // The process left the table between the listing and the read: it owns nothing.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            // Anything else is a blind spot, not a process without a command line.
            Err(error) => return Err(error),
        }
    }
    Ok(None)
}

/// What a boot may do at the control socket path.
#[derive(Debug, PartialEq, Eq)]
enum SocketAction {
    /// Nothing there, or nothing that a new `swtpm` has to clear: it binds the path itself.
    Use,
    /// A socket file a crashed run left behind: the new daemon cannot bind on top of it.
    RemoveStaleSocket,
}

/// Decide what may happen at the control socket path, before anything there is touched.
///
/// The process table is the only thing that tells a stale socket from a live daemon's
/// endpoint, so the order is the point: a table that could not be read is refused, not
/// reported as "no daemon", because that answer is exactly what licenses the removal below it.
fn plan_socket_action(
    state_dir: &Path,
    socket_path: &Path,
    socket: &ControlSocket,
    live: std::io::Result<Option<u32>>,
) -> Result<SocketAction> {
    match live {
        Ok(Some(pid)) => bail!(
            "a `swtpm` for this Windows guest's TPM is already running (pid {pid}) and is \
             serving {}: Qlean will not start a second one on the same state directory, \
             because both would write the same state file and the guest's sealed secrets \
             could be lost. Stop that process (or the machine it belongs to) and boot again",
            state_dir.display()
        ),
        Ok(None) => match socket {
            ControlSocket::Absent => Ok(SocketAction::Use),
            ControlSocket::Socket => Ok(SocketAction::RemoveStaleSocket),
            ControlSocket::Foreign(kind) => bail!(
                "the swtpm control socket path {} is {kind}, so no TPM could be reached through \
                 it: Qlean keeps its own socket there and does not create that entry, so nothing \
                 was used or deleted. Remove it and boot again",
                socket_path.display()
            ),
        },
        Err(error) => bail!(
            "could not read the process table to check whether a `swtpm` is already serving the \
             TPM state directory {}: {error}\n\
             Qlean removes the control socket {} only when it can prove no daemon is serving \
             it, and a second `swtpm` on the same state directory can lose the guest's sealed \
             secrets (on Windows: a BitLocker recovery prompt). Nothing was removed. Make \
             /proc readable (mount it, or run as a user that can) and boot again",
            state_dir.display(),
            socket_path.display()
        ),
    }
}

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

    // The per-VM vars image is a plain file the run directory owns, and Qlean never creates a
    // link there. `is_file()` follows links, and R220 showed both halves of the cost: a link to
    // the shared template took the reuse branch, whose `chmod` landed on the *template* (0600,
    // breaking every other VM on the host), and a dangling link took the copy branch, which
    // created the file wherever the link pointed - outside the run directory. Stat the entry
    // itself and refuse anything that is not a regular file, without reading or writing it.
    let existing = match std::fs::symlink_metadata(&dest) {
        Ok(meta) => Some(meta),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to stat the per-VM OVMF vars image {}",
                    dest.display()
                )
            });
        }
    };
    if let Some(meta) = existing {
        anyhow::ensure!(
            meta.file_type().is_file(),
            "the per-VM OVMF vars image {} is {}: Qlean keeps the guest's NVRAM in a plain file \
             inside the run directory and does not follow a link there, so nothing was read or \
             written. Remove it and boot again",
            dest.display(),
            not_a_plain_file(&dest, &meta)
        );
        // The per-VM vars image survives restarts and holds the guest's NVRAM, so it is not
        // overwritten. A size that no longer matches the template means it was written by a
        // different OVMF build (the distribution upgraded the firmware) or left truncated:
        // booting on it either corrupts NVRAM or fails inside the firmware.
        let dest_len = meta.len();
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

/// What one bounded wait for a child told us.
///
/// The timeout wrapper's own `is_err` answers only "did the grace period expire", so
/// `Ok(Err(_))` - `wait` itself failing - used to fall through the same branch as an exit:
/// `stop` returned as if the TPM had shut down while nobody had confirmed it, and the caller
/// carried on to reuse the state directory that a still-running `swtpm` may own.
#[derive(Debug, PartialEq, Eq)]
enum WaitOutcome {
    /// The child exited.
    Exited,
    /// The grace period expired with the child still running.
    TimedOut,
    /// `wait` failed, so the child's fate is unknown.
    Failed(String),
}

fn wait_outcome(
    waited: std::result::Result<
        std::io::Result<std::process::ExitStatus>,
        tokio::time::error::Elapsed,
    >,
) -> WaitOutcome {
    match waited {
        Ok(Ok(_)) => WaitOutcome::Exited,
        Ok(Err(error)) => WaitOutcome::Failed(error.to_string()),
        Err(_) => WaitOutcome::TimedOut,
    }
}

/// How often the synchronous stop asks the child whether it has exited.
const SYNC_STOP_POLL: Duration = Duration::from_millis(20);

/// What the last synchronous probe of the child told us.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum WaitProbe {
    /// The child has exited and was reaped.
    Exited,
    /// The child is still running.
    StillRunning,
    /// The probe itself failed, so the child's fate is unknown.
    Failed,
}

/// What the synchronous stop does next, given the last probe and the elapsed grace.
///
/// Pure for the same reason [`wait_outcome`] is: the three ways out of the loop are the whole
/// contract, and two of them are hard to reach with a real process - a child the kernel cannot
/// interrupt, and a probe that fails. The loop used to have one way out (kill it and return),
/// which reported neither a confirmed exit nor a confirmed failure.
#[derive(Debug, PartialEq, Eq)]
enum SyncStopStep {
    /// Confirmed gone: nothing to kill, nothing to report.
    Exited,
    /// Still inside the grace: let it flush its state.
    KeepWaiting,
    /// The grace expired, or nobody can say what the child is doing: kill it.
    Kill,
}

fn sync_stop_step(probe: WaitProbe, elapsed: Duration, grace: Duration) -> SyncStopStep {
    match probe {
        WaitProbe::Exited => SyncStopStep::Exited,
        WaitProbe::StillRunning if elapsed < grace => SyncStopStep::KeepWaiting,
        WaitProbe::StillRunning => SyncStopStep::Kill,
        // A probe that failed is not a child that is alive, but it is certainly not a child
        // that is confirmed gone, so the kill is the only remaining move - and the caller has
        // already been told the probe failed.
        WaitProbe::Failed => SyncStopStep::Kill,
    }
}

/// Ask a child process to terminate, so it can flush its state first.
///
/// `Child::start_kill` only sends `SIGKILL`, which gives `swtpm` no chance to write the TPM
/// state file. Non-Unix hosts keep the old behaviour (they cannot run a Windows guest).
/// End a `swtpm` the one way Qlean ends one: ask it to terminate, give it the grace period to
/// flush its TPM state, and only then kill it.
///
/// Returns whether the process is *confirmed* gone.
///
/// The shutdown ladder and the startup timeout are the same question - "how does this process
/// end?" - and they answered it differently: [`Swtpm::stop`] asked politely, because a `SIGKILL`
/// leaves a half-written `tpm2-00.permall` behind and the guest loses the TPM identity it sealed
/// secrets against (on Windows: BitLocker recovery), while [`Swtpm::start`] `SIGKILL`ed a `swtpm`
/// that had not opened its control socket within ten seconds and said nothing about whether it
/// was gone. One invariant, two answers - and the impatient one ran on the path a slow host
/// takes.
async fn terminate_and_confirm(child: &mut tokio::process::Child) -> bool {
    terminate_and_confirm_within(child, SHUTDOWN_GRACE).await
}

/// [`terminate_and_confirm`] with the grace as an argument, so the tests drive this exact code.
async fn terminate_and_confirm_within(child: &mut tokio::process::Child, grace: Duration) -> bool {
    signal_terminate(child);
    match wait_outcome(tokio::time::timeout(grace, child.wait()).await) {
        WaitOutcome::Exited => true,
        WaitOutcome::TimedOut => {
            warn!("swtpm did not exit within {grace:?}; killing it");
            kill_and_reap(child).await;
            child.try_wait().is_ok_and(|status| status.is_some())
        }
        WaitOutcome::Failed(error) => {
            warn!(
                "could not wait for swtpm to exit ({error}); it may still be running, so its \
                 TPM state directory is not vouched for"
            );
            kill_and_reap(child).await;
            child.try_wait().is_ok_and(|status| status.is_some())
        }
    }
}

/// Kill the child and wait a bounded time for it to leave.
async fn kill_and_reap(child: &mut tokio::process::Child) {
    let _ = child.start_kill();
    let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
}

/// What a start that timed out waiting for the control socket says.
///
/// The old message stopped at "timed out", which left the caller without the two facts that
/// decide what to do next: which process was being started, and whether it is still there. A
/// `swtpm` that survived the timeout is still writing the state directory, and the next start
/// refuses that directory for exactly that reason (see [`live_swtpm_on`]).
fn startup_timeout_message(socket: &Path, pid: Option<u32>, stopped: bool) -> String {
    let owner = match pid {
        Some(pid) => format!("pid {pid}"),
        None => "the swtpm it started".to_string(),
    };
    let ending = if stopped {
        "was asked to stop and is confirmed gone"
    } else {
        "could not be stopped and may still be writing its TPM state"
    };
    format!(
        "timed out waiting for the swtpm control socket at {}: the {owner} {ending}",
        socket.display()
    )
}

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
        // The TPM state is per-VM secret material and `swtpm` starts writing into it as soon
        // as it runs, so the directory has to be owner-only from creation: creating it with
        // the umask's permissions and `chmod`ing it afterwards is the window R97 closed.
        crate::utils::create_owner_only_dir_all(&state_dir)
            .with_context(|| format!("failed to create TPM state dir {}", state_dir.display()))?;
        let socket = run_dir.join("swtpm.sock");
        // Before anything at the socket path is touched: `swtpm` does not lock its state
        // directory, so a daemon that outlived the qlean process that started it keeps
        // serving this VM's TPM. Removing its control socket would leave it running and
        // unreachable, and the second daemon started below would write the same state file as
        // the first - on Windows that is a lost TPM identity and a BitLocker recovery prompt.
        let live = live_swtpm_on(&state_dir);
        let state = control_socket_state(&socket).with_context(|| {
            format!(
                "failed to inspect the swtpm control socket path {}",
                socket.display()
            )
        })?;
        match plan_socket_action(&state_dir, &socket, &state, live)? {
            SocketAction::Use => {}
            SocketAction::RemoveStaleSocket => {
                // A crashed `swtpm` leaves its socket file behind, and the new one cannot
                // bind on top of it. Only the socket itself is removed: it is Qlean's own
                // endpoint, named after the run directory.
                std::fs::remove_file(&socket).with_context(|| {
                    format!(
                        "failed to remove the stale swtpm control socket {}",
                        socket.display()
                    )
                })?;
                debug!(
                    "Removed the stale swtpm control socket at {}",
                    socket.display()
                );
            }
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
            if control_socket_state(&socket)
                .with_context(|| {
                    format!(
                        "failed to inspect the swtpm control socket path {}",
                        socket.display()
                    )
                })?
                .is_socket()
            {
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
                let pid = child.id();
                let stopped = terminate_and_confirm(&mut child).await;
                bail!("{}", startup_timeout_message(&socket, pid, stopped));
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
    ///
    /// Returns whether the process is *confirmed* gone. A `wait` that itself failed is not
    /// confirmation: the caller is about to rebuild this machine's TPM state directory, and
    /// nobody has vouched that its owner is still there.
    pub(crate) async fn stop(&mut self) -> bool {
        terminate_and_confirm(&mut self.child).await
    }

    /// Stop the process from synchronous code (for example `Drop`).
    ///
    /// `Drop` cannot await, so this signals the child, waits synchronously for a bounded
    /// time and then kills it. The wait matters: dropping a child configured with
    /// `kill_on_drop` would `SIGKILL` it immediately after the signal.
    ///
    /// Returns whether the process is *confirmed* gone, the same promise [`Swtpm::stop`] makes
    /// for the asynchronous path. Falling off the end of the wait used to return nothing and say
    /// nothing, so a `Drop` carried on to remove the run directory - and with it the TPM state
    /// directory - while the process that owns them might still have been writing to it.
    pub(crate) fn stop_now(&mut self) -> bool {
        self.stop_now_within(SHUTDOWN_GRACE)
    }

    /// [`Swtpm::stop_now`] with the grace as an argument, so the tests drive this exact code.
    fn stop_now_within(&mut self, grace: Duration) -> bool {
        signal_terminate(&mut self.child);
        let started = Instant::now();
        loop {
            let probe = match self.child.try_wait() {
                Ok(Some(_)) => WaitProbe::Exited,
                Ok(None) => WaitProbe::StillRunning,
                Err(error) => {
                    warn!("failed to wait for swtpm: {error}");
                    WaitProbe::Failed
                }
            };
            match sync_stop_step(probe, started.elapsed(), grace) {
                SyncStopStep::Exited => return true,
                SyncStopStep::KeepWaiting => std::thread::sleep(SYNC_STOP_POLL),
                SyncStopStep::Kill => {
                    if probe == WaitProbe::StillRunning {
                        warn!("swtpm did not exit within {grace:?}; killing it");
                    }
                    return self.kill_now(grace);
                }
            }
        }
    }

    /// `SIGKILL` the child and report whether it is confirmed gone.
    ///
    /// `SIGKILL` is not the same as "gone": the signal has to be delivered (`start_kill`) and the
    /// child has to be reaped (`try_wait`), and a process the kernel cannot interrupt stays
    /// behind. Both failures are warnings, because this runs from `Drop`, where returning early
    /// is the only other option - but the return value has to say "not confirmed" so the caller
    /// does not reuse a directory a live process still holds.
    fn kill_now(&mut self, grace: Duration) -> bool {
        if let Err(error) = self.child.start_kill() {
            warn!("failed to kill swtpm: {error}");
            return false;
        }
        let started = Instant::now();
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => return true,
                Ok(None) if started.elapsed() < grace => std::thread::sleep(SYNC_STOP_POLL),
                Ok(None) => {
                    warn!("swtpm is still running {grace:?} after SIGKILL");
                    return false;
                }
                Err(error) => {
                    warn!("could not reap swtpm after SIGKILL ({error}); it may still be running");
                    return false;
                }
            }
        }
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

    /// The smoke test's swtpm fixture is the command line [`swtpm_args`] builds.
    ///
    /// `tests/windows_machine.rs` finds the TPM state directory by reading `swtpm`'s argv for
    /// `--tpmstate dir=`. The argv it reads there is a hand-written string and says so - "a
    /// fixture that drifts from them tests the fixture" - while nothing compared it with this
    /// function. A drifted fixture would not fail here; it would fail on the one host with a
    /// licensed image, after a 15 minute boot, as "the restart reused the same vars" being
    /// decided from a directory that was never parsed.
    ///
    /// Two checks, because the fixture can drift in two ways: the options the parsers read
    /// (`dir=<state dir>` and `type=...,mode=0600`) have to be in the fixture as this function
    /// writes them, and `--tpmstate` has to sit directly in front of its `dir=` value, since
    /// that adjacency is how `tpm_state_dir` finds the directory at all.
    #[test]
    fn the_smoke_test_arg_fixture_is_the_swtpm_command_line_the_launch_builds() {
        const SMOKE: &str = include_str!("../tests/windows_machine.rs");

        let args = swtpm_args(
            Path::new("/run/qlean/VM-1/tpm"),
            Path::new("/run/qlean/VM-1/swtpm.sock"),
            Path::new("/run/qlean/VM-1/swtpm.log"),
        );
        // The two options whose contents decide what the smoke test can observe: where the
        // state lives, and the control socket's mode.
        for option in args
            .iter()
            .filter(|argument| argument.starts_with("dir=") || argument.starts_with("type="))
        {
            assert!(
                SMOKE.contains(option.as_str()),
                "the smoke test no longer carries swtpm's `{option}`, so the fixture it parses \
                 is not the command line this crate launches"
            );
        }
        // The flag that makes the state directory appear at all.
        let at = args
            .iter()
            .position(|argument| argument == "--tpmstate")
            .expect("swtpm is told where its state lives");
        let parsed = SMOKE
            .split_whitespace()
            .collect::<Vec<_>>()
            .windows(2)
            .any(|pair| pair[0] == args[at] && pair[1] == args[at + 1]);
        assert!(
            parsed,
            "the smoke test does not read `{} {}`: `tpm_state_dir` would answer `None`",
            args[at],
            args[at + 1]
        );
    }

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
    fn test_falling_back_to_a_plain_pair_is_never_silent() {
        // The Arch layout: a `secboot` code image with no enrolled vars template next to a
        // usable plain pair. The fallback itself is correct, but a Windows 11 image will
        // refuse to install, so the user has to be told why Secure Boot is off.
        let secboot_code = Path::new("/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd");
        let plain_vars = Path::new("/usr/share/edk2/x64/OVMF_VARS.4m.fd");
        let plain_code = Path::new("/usr/share/edk2/x64/OVMF_CODE.4m.fd");
        let probe = |path: &Path| path == secboot_code || path == plain_vars || path == plain_code;

        let resolved = resolve_ovmf_with(&probe, &ms_only);
        let paths = resolved.paths.expect("the plain candidate is usable");
        assert!(!paths.secure_boot);

        let notice = secure_boot_skipped_notice(&resolved.skipped)
            .expect("a skipped Secure Boot pair must produce a notice");
        assert!(notice.contains("Secure Boot is disabled"), "{notice}");
        assert!(
            notice.contains("Windows 11 requires Secure Boot"),
            "{notice}"
        );
        assert!(
            notice.contains("no Microsoft Secure Boot keys"),
            "the reason must be carried, not just the verdict: {notice}"
        );
        assert!(notice.contains(ENV_OVMF_VARS), "{notice}");
    }

    #[test]
    fn test_a_secure_boot_pair_produces_no_fallback_notice() {
        // The `.ms` template is enrolled, so the first candidate wins and nothing was
        // skipped: warning about Secure Boot here would be a false alarm.
        let code = Path::new("/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd");
        let ms_vars = Path::new("/usr/share/edk2/x64/OVMF_VARS.4m.ms.fd");
        let probe = |path: &Path| path == code || path == ms_vars;

        let resolved = resolve_ovmf_with(&probe, &ms_only);
        assert!(resolved.paths.expect("the pair is usable").secure_boot);
        assert!(resolved.skipped.is_empty(), "{:?}", resolved.skipped);
        assert_eq!(secure_boot_skipped_notice(&resolved.skipped), None);
    }

    #[test]
    fn test_the_fallback_notice_names_every_skipped_pair() {
        let skipped = vec![
            "skipped A: the vars template carries no Microsoft Secure Boot keys".to_string(),
            "skipped B: the vars template could not be read (permission denied)".to_string(),
        ];
        let notice = secure_boot_skipped_notice(&skipped).expect("two reasons are worth saying");
        for reason in &skipped {
            assert!(notice.contains(reason), "{notice}");
        }
        assert_eq!(secure_boot_skipped_notice(&[]), None);
    }

    /// Check the resolver against the OVMF package really installed on this host.
    ///
    /// Every other firmware test injects probes, so nothing proved that the candidate
    /// paths match what a distribution actually ships. Ignored because a host without
    /// `edk2-ovmf`/`ovmf` has nothing to resolve; run it where the package is installed:
    ///
    /// ```text
    /// cargo test --lib -- --ignored firmware_resolve
    /// ```
    #[test]
    #[ignore = "needs the distro OVMF package installed; run with --ignored"]
    fn test_firmware_resolve_accepts_the_host_package_layout() {
        let paths = resolve_ovmf().expect("this host has a usable OVMF pair installed");
        assert!(paths.code.is_file(), "{}", paths.code.display());
        assert!(
            paths.vars_template.is_file(),
            "{}",
            paths.vars_template.display()
        );
        assert_eq!(
            paths.secure_boot,
            is_secure_boot_name(&paths.code),
            "the Secure Boot flag must follow the code image name"
        );
        let code_len = std::fs::metadata(&paths.code)
            .expect("code is readable")
            .len();
        let vars_len = std::fs::metadata(&paths.vars_template)
            .expect("vars is readable")
            .len();
        assert!(
            vars_len <= code_len,
            "the vars template must not be larger than the code image: {vars_len} > {code_len}"
        );
        if paths.secure_boot {
            assert!(
                vars_template_enrolls_microsoft_keys(&paths.vars_template)
                    .expect("the vars template is readable"),
                "a Secure Boot pair must come from an enrolled template"
            );
        }
        // Same probes `resolve_ovmf` uses, so this records the *real* decision including
        // the reasons it skipped a Secure Boot pair: on the Arch layout the skipped list is
        // what feeds the "Secure Boot is disabled" warning.
        let probed = resolve_ovmf_with(&|path| path.is_file(), &|path| {
            vars_template_enrolls_microsoft_keys(path)
        });
        let probed_paths = probed.paths.as_ref().expect("the same pair resolves");
        assert_eq!(probed_paths.code, paths.code, "both paths must agree");
        assert_eq!(
            secure_boot_skipped_notice(&probed.skipped).is_some(),
            !paths.secure_boot,
            "a non-Secure-Boot fallback must always carry a notice: skipped={:?}",
            probed.skipped
        );
        println!(
            "resolved OVMF: code={} vars={} secure_boot={} skipped={:?}",
            paths.code.display(),
            paths.vars_template.display(),
            paths.secure_boot,
            probed.skipped
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

    /// A link in place of the per-VM vars image is refused, not followed.
    ///
    /// R220: `dest.is_file()` follows links. A link to a shared copy of the template took the
    /// reuse branch and the `chmod` landed on the *file the link named* - 0644 became 0600, so a
    /// shared firmware image was hardened for every other VM on the host, and a path outside the
    /// run directory was modified by a run that believes it owns only its own directory.
    #[test]
    #[cfg(unix)]
    fn test_prepare_vars_refuses_a_linked_vars_image() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_dir("vars-link");
        let run_dir = root.join("run");
        std::fs::create_dir_all(&run_dir).unwrap();
        let code = root.join("code.fd");
        let vars_template = root.join("vars.fd");
        write_file(&code, 64);
        write_file(&vars_template, 64);
        let shared = root.join("shared-vars.fd");
        write_file(&shared, 64);
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o644)).unwrap();
        let dest = run_dir.join("ovmf_vars.fd");
        std::os::unix::fs::symlink(&shared, &dest).unwrap();
        let firmware = FirmwarePaths {
            code,
            vars_template,
            secure_boot: false,
        };

        let err = prepare_vars(&run_dir, &firmware)
            .expect_err("a link is not the per-VM vars image")
            .to_string();
        assert!(
            err.contains("a symlink to"),
            "must say what it found: {err}"
        );
        assert!(err.contains(&shared.display().to_string()), "{err}");
        assert!(err.contains("Remove it"), "must say how to recover: {err}");
        // Nothing behind the link may be touched.
        let mode = std::fs::metadata(&shared).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644, "the linked file was chmodded to {mode:o}");
        assert_eq!(std::fs::read(&shared).unwrap(), vec![0u8; 64]);
        assert!(
            std::fs::symlink_metadata(&dest)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the link must be left for the reader to inspect"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A dangling link is not a missing file: the copy branch would create its target.
    ///
    /// `is_file()` answers false for a link whose target does not exist, so R220's second half
    /// was `fs::copy` running with `dest` as the link path: `open(2)` on the destination follows
    /// the link, so the template was written to whatever path the link named - the run created a
    /// file outside its own directory and then chmodded it.
    #[test]
    #[cfg(unix)]
    fn test_prepare_vars_does_not_create_the_target_of_a_dangling_link() {
        let root = temp_dir("vars-dangling");
        let run_dir = root.join("run");
        std::fs::create_dir_all(&run_dir).unwrap();
        let code = root.join("code.fd");
        let vars_template = root.join("vars.fd");
        write_file(&code, 64);
        write_file(&vars_template, 64);
        let outside = root.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let created = outside.join("created.fd");
        let dest = run_dir.join("ovmf_vars.fd");
        std::os::unix::fs::symlink(&created, &dest).unwrap();
        let firmware = FirmwarePaths {
            code,
            vars_template,
            secure_boot: false,
        };

        let err = prepare_vars(&run_dir, &firmware)
            .expect_err("a dangling link must not be filled in")
            .to_string();
        assert!(err.contains("a symlink to"), "{err}");
        assert!(
            !created.exists(),
            "the copy branch created {} outside the run directory",
            created.display()
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_prepare_vars_refuses_a_directory_in_place_of_the_vars_image() {
        let root = temp_dir("vars-dir");
        let run_dir = root.join("run");
        std::fs::create_dir_all(&run_dir).unwrap();
        let code = root.join("code.fd");
        let vars_template = root.join("vars.fd");
        write_file(&code, 64);
        write_file(&vars_template, 64);
        std::fs::create_dir_all(run_dir.join("ovmf_vars.fd")).unwrap();
        let firmware = FirmwarePaths {
            code,
            vars_template,
            secure_boot: false,
        };

        // A directory used to fall through to the copy branch, where the only report was an
        // `Is a directory` from `copy`, one layer below the file Qlean was asked to prepare.
        let err = prepare_vars(&run_dir, &firmware)
            .expect_err("a directory is not the per-VM vars image")
            .to_string();
        assert!(err.contains("a directory"), "{err}");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The control socket path is classified, not merely "does something exist".
    ///
    /// Before R228 `Swtpm::start` asked `path.exists()` and nothing else. Measured against a
    /// real `swtpm` 0.10.2 in the container: with a directory at the socket path, `start`
    /// returned `Ok` in 0.02s, `socket()` named the directory, and the first boot went on to
    /// hand QEMU `-chardev socket,path=<a directory>`. The gap is visible without any program
    /// at all, which is why the classification is a function of its own.
    #[test]
    fn test_the_control_socket_path_is_classified_by_shape() {
        let root = temp_dir("swtpm-socket-shape");
        let socket = root.join("swtpm.sock");

        assert_eq!(
            control_socket_state(&socket).unwrap(),
            ControlSocket::Absent
        );

        write_file(&socket, 16);
        assert_eq!(
            control_socket_state(&socket).unwrap(),
            ControlSocket::Foreign("a regular file".to_string())
        );
        assert!(!control_socket_state(&socket).unwrap().is_socket());

        std::fs::remove_file(&socket).unwrap();
        std::fs::create_dir_all(&socket).unwrap();
        assert_eq!(
            control_socket_state(&socket).unwrap(),
            ControlSocket::Foreign("a directory".to_string())
        );

        // A real socket is the only shape that answers "the TPM's endpoint is there".
        #[cfg(unix)]
        {
            std::fs::remove_dir_all(&socket).unwrap();
            let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
            assert_eq!(
                control_socket_state(&socket).unwrap(),
                ControlSocket::Socket
            );
            assert!(control_socket_state(&socket).unwrap().is_socket());
            drop(listener);
        }

        // A link is not the socket either: following it would hand QEMU somebody else's
        // endpoint, and the run directory is Qlean's own - it never creates a link there.
        std::fs::remove_file(&socket).ok();
        std::fs::create_dir_all(root.join("elsewhere")).unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(root.join("elsewhere"), &socket).unwrap();
            let state = control_socket_state(&socket).unwrap();
            assert!(
                matches!(&state, ControlSocket::Foreign(kind) if kind.starts_with("a symlink to ")),
                "{state:?}"
            );
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A foreign entry is refused by name, and the user's entry is left where it is.
    ///
    /// `start` cannot be entered without spawning `swtpm`, but the refusal is decided before
    /// the spawn: a run directory whose socket path holds a directory fails here without any
    /// program installed, which is what makes this testable on a host without `swtpm`.
    #[tokio::test]
    async fn test_a_foreign_entry_at_the_control_socket_path_is_refused_not_deleted() {
        for (entry, expected) in [("directory", "a directory"), ("file", "a regular file")] {
            let root = temp_dir(&format!("swtpm-foreign-{entry}"));
            let run_dir = root.join("run");
            std::fs::create_dir_all(&run_dir).unwrap();
            let socket = run_dir.join("swtpm.sock");
            if entry == "directory" {
                std::fs::create_dir_all(&socket).unwrap();
            } else {
                std::fs::write(&socket, b"hand-made").unwrap();
            }

            let error = match Swtpm::start(&run_dir).await {
                Ok(_) => panic!("a non-socket at the control socket path is not a running TPM"),
                Err(error) => error.to_string(),
            };
            assert!(
                error.contains("swtpm control socket path") && error.contains(expected),
                "the refusal has to name the entry it found: {error}"
            );
            assert!(
                error.contains("Remove it and boot again"),
                "the refusal has to say what to do: {error}"
            );
            assert!(
                error.contains(&socket.display().to_string()),
                "the refusal has to name the path: {error}"
            );
            assert!(
                socket.exists(),
                "the entry is the user's, so Qlean refuses it instead of deleting it"
            );

            let _ = std::fs::remove_dir_all(&root);
        }
    }

    /// A command line names this VM's TPM state only when it is a `swtpm` and the directory
    /// follows `--tpmstate`.
    ///
    /// `swtpm` does not lock its state directory: two daemons with the same
    /// `--tpmstate dir=` both run (measured against `swtpm` 0.10.2 in the container). The
    /// identity therefore has to come off `/proc/<pid>/cmdline`, and it has to be exact -
    /// "a process naming a similar path" would refuse a start for a VM that owns nothing.
    #[test]
    fn test_a_cmdline_names_the_tpm_state_directory_only_next_to_its_flag() {
        let state = Path::new("/qlean/runs/abc/tpm");
        let cmdline = |args: &[&str]| args.join("\0").into_bytes();

        // What `swtpm_args` builds for this VM.
        assert!(cmdline_is_swtpm_for(
            &cmdline(&[
                "/usr/bin/swtpm",
                "socket",
                "--tpm2",
                "--tpmstate",
                "dir=/qlean/runs/abc/tpm,mode=0600",
                "--ctrl",
                "type=unixio,path=/qlean/runs/abc/swtpm.sock",
            ]),
            state
        ));
        // The program is `argv[0]`: naming `swtpm` in a later argument does not make a
        // process one, and a log path is exactly that trap.
        assert!(!cmdline_is_swtpm_for(
            &cmdline(&[
                "/usr/bin/qemu-system-x86_64",
                "-chardev",
                "socket,path=/usr/bin/swtpm",
                "--tpmstate",
                "dir=/qlean/runs/abc/tpm",
            ]),
            state
        ));
        // Another VM's `swtpm` serves its own state directory, not this one.
        assert!(!cmdline_is_swtpm_for(
            &cmdline(&["swtpm", "--tpmstate", "dir=/qlean/runs/other/tpm,mode=0600",]),
            state
        ));
        // A prefix is not the directory: `/tpm2` is a different VM.
        assert!(!cmdline_is_swtpm_for(
            &cmdline(&["swtpm", "--tpmstate", "dir=/qlean/runs/abc/tpm2"]),
            state
        ));
        // The value only counts where `swtpm` reads it: next to `--tpmstate`. A stray
        // argument that happens to spell the directory proves nothing.
        assert!(!cmdline_is_swtpm_for(
            &cmdline(&[
                "swtpm",
                "--log",
                "dir=/qlean/runs/abc/tpm",
                "file=/dev/null"
            ]),
            state
        ));
        // No arguments at all: the program alone cannot own a directory.
        assert!(!cmdline_is_swtpm_for(b"swtpm\0", state));
        assert!(!cmdline_is_swtpm_for(b"", state));
    }

    /// "I could not look" is not "there is nothing there".
    ///
    /// `start` removes a socket at the control path only because the process table says no
    /// daemon serves it. A table that cannot be read is the one input that used to be folded
    /// into that answer (`read_dir("/proc").ok()?`), which turned "I cannot see the daemon" into
    /// "there is no daemon" and licensed the removal of a live endpoint, followed by a second
    /// `swtpm` on the same `tpm2-00.permall`.
    #[test]
    fn test_a_proc_table_that_cannot_be_read_is_not_a_clean_one() {
        let root = temp_dir("swtpm-proc-unreadable");
        let state_dir = root.join("tpm");
        std::fs::create_dir_all(&state_dir).unwrap();
        let socket = root.join("swtpm.sock");

        let error = swtpm_in(&root.join("no-such-proc"), &state_dir)
            .expect_err("a table that cannot be read is not proof that no daemon exists");
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound, "{error}");

        let error = plan_socket_action(&state_dir, &socket, &ControlSocket::Socket, Err(error))
            .expect_err("a boot that could not check must not delete what it could not check");
        let text = error.to_string();
        assert!(
            text.contains(&state_dir.display().to_string()),
            "the refusal has to name the state directory it protects: {text}"
        );
        assert!(
            text.contains("Nothing was removed"),
            "the refusal has to say the socket is still there: {text}"
        );
        assert!(
            text.contains("second `swtpm`"),
            "the refusal has to say what the removal would risk: {text}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The table is read for the daemon's own command line, not for a name in the path.
    #[test]
    fn test_the_process_table_is_read_for_a_daemon_serving_this_state_directory() {
        let root = temp_dir("swtpm-proc-table");
        let state_dir = root.join("tpm");
        let other_state = root.join("other-tpm");
        std::fs::create_dir_all(&state_dir).unwrap();
        let proc_root = root.join("proc");
        let write_cmdline = |pid: &str, argv: &[&str]| {
            let dir = proc_root.join(pid);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("cmdline"), argv.join("\0")).unwrap();
        };
        // The daemon this VM's state directory belongs to (pid 100).
        write_cmdline(
            "100",
            &[
                "swtpm",
                "socket",
                "--tpmstate",
                &format!("dir={},mode=0600", state_dir.display()),
            ],
        );
        // A QEMU that merely mentions the directory.
        write_cmdline(
            "200",
            &[
                "qemu-system-x86_64",
                "--tpmstate",
                &format!("dir={}", state_dir.display()),
            ],
        );
        // A `swtpm` for a *different* state directory: a prefix, not a match.
        write_cmdline(
            "300",
            &[
                "swtpm",
                "--tpmstate",
                &format!("dir={}", other_state.display()),
            ],
        );
        // A table entry that is not a pid (a `swtpm` must not be found by its name alone).
        write_cmdline(
            "not-a-pid",
            &[
                "swtpm",
                "--tpmstate",
                &format!("dir={}", state_dir.display()),
            ],
        );

        assert_eq!(swtpm_in(&proc_root, &state_dir).unwrap(), Some(100));

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A `cmdline` that exists but cannot be read is a blind spot, not an empty process.
    #[test]
    fn test_a_process_table_entry_that_cannot_be_read_is_not_skipped() {
        let root = temp_dir("swtpm-proc-blind");
        let state_dir = root.join("tpm");
        std::fs::create_dir_all(&state_dir).unwrap();
        let proc_root = root.join("proc");
        // `cmdline` as a directory: it exists, and reading it fails with something that is not
        // `NotFound`, which is the shape a hidden `/proc/<pid>/cmdline` takes.
        std::fs::create_dir_all(proc_root.join("400").join("cmdline")).unwrap();

        let error = swtpm_in(&proc_root, &state_dir)
            .expect_err("an entry that cannot be read is not an entry without a command line");
        assert_ne!(error.kind(), std::io::ErrorKind::NotFound, "{error}");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// What may happen at the socket path, for every combination of answers.
    #[test]
    fn test_only_a_clean_scan_lets_a_stale_socket_be_removed() {
        let root = temp_dir("swtpm-socket-plan");
        let state_dir = root.join("tpm");
        std::fs::create_dir_all(&state_dir).unwrap();
        let socket = root.join("swtpm.sock");

        assert_eq!(
            plan_socket_action(&state_dir, &socket, &ControlSocket::Absent, Ok(None)).unwrap(),
            SocketAction::Use
        );
        assert_eq!(
            plan_socket_action(&state_dir, &socket, &ControlSocket::Socket, Ok(None)).unwrap(),
            SocketAction::RemoveStaleSocket
        );

        // A live daemon is refused by pid, whatever sits at the path.
        for shape in [ControlSocket::Absent, ControlSocket::Socket] {
            let error = plan_socket_action(&state_dir, &socket, &shape, Ok(Some(4242)))
                .expect_err("a live daemon must stop the boot");
            let text = error.to_string();
            assert!(text.contains("pid 4242"), "{text}");
            assert!(text.contains("will not start a second one"), "{text}");
        }

        // An entry Qlean did not create is named and left alone, and the message keeps the path.
        let error = plan_socket_action(
            &state_dir,
            &socket,
            &ControlSocket::Foreign("a FIFO (named pipe)".to_string()),
            Ok(None),
        )
        .expect_err("a foreign entry is refused, not deleted");
        let text = error.to_string();
        assert!(text.contains("a FIFO (named pipe)"), "{text}");
        assert!(text.contains(&socket.display().to_string()), "{text}");
        assert!(text.contains("nothing was used or deleted"), "{text}");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A FIFO or a device node is named as itself, not as "a regular file".
    ///
    /// The sentence is all the user has before deleting the entry, so the one property it
    /// reports has to be the entry's: a FIFO described as "a regular file" reads as a Qlean
    /// mistake and invites the reader to distrust a refusal that was right.
    #[test]
    #[cfg(unix)]
    fn test_a_special_file_at_the_socket_path_is_named_as_itself() {
        let root = temp_dir("swtpm-socket-special");

        // A character device, from a path every Unix host has.
        assert_eq!(
            control_socket_state(Path::new("/dev/null")).unwrap(),
            ControlSocket::Foreign("a character device".to_string())
        );

        // A FIFO needs `mkfifo`; where it is missing the shape cannot be built at all.
        let fifo = root.join("swtpm.sock");
        let made = std::process::Command::new("mkfifo").arg(&fifo).status();
        if let Ok(status) = made
            && status.success()
        {
            assert_eq!(
                control_socket_state(&fifo).unwrap(),
                ControlSocket::Foreign("a FIFO (named pipe)".to_string())
            );
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A `swtpm` that is still serving this VM's TPM is refused before its socket is touched.
    ///
    /// The socket file a crashed run leaves behind and the socket a *live* daemon is serving
    /// look the same, so deleting it "because it is stale" cuts the endpoint out from under a
    /// running TPM and then starts a second daemon on the same state directory. The process
    /// whose `argv` names this VM's `--tpmstate` is the only witness, and it has to be
    /// consulted before the removal.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_a_live_swtpm_for_this_vm_is_refused_before_its_socket_is_touched() {
        let root = temp_dir("swtpm-live-owner");
        let run_dir = root.join("run");
        let state_dir = run_dir.join("tpm");
        std::fs::create_dir_all(&state_dir).unwrap();

        // A live process whose command line says it serves this VM's TPM state. `argv[0]` is
        // the deciding field, so the process is reached through a link named `swtpm`; the
        // trailing `: ` keeps `sh` from `exec`ing `sleep` and dropping the arguments.
        let program = root.join("swtpm");
        std::os::unix::fs::symlink("/bin/sh", &program).unwrap();
        let mut fake = tokio::process::Command::new(&program)
            .arg("-c")
            .arg("sleep 30; :")
            .arg("--tpmstate")
            .arg(format!("dir={}", state_dir.display()))
            .kill_on_drop(true)
            .spawn()
            .expect("sh is available");
        let pid = fake.id().expect("the fake has a pid");

        // The endpoint the fake owns, in the shape a crashed run leaves behind.
        let socket = run_dir.join("swtpm.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();

        // Give the process table a moment to show the command line.
        let mut found = None;
        for _ in 0..100 {
            found = live_swtpm_on(&state_dir).expect("this host can read /proc");
            if found == Some(pid) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            found,
            Some(pid),
            "the fake has to be found by its command line"
        );

        let error = match Swtpm::start(&run_dir).await {
            Ok(_) => panic!("a live TPM on this state directory is not a second TPM to start"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains(&format!("pid {pid}"))
                && error.contains(&state_dir.display().to_string()),
            "the refusal has to name the process and the directory it serves: {error}"
        );
        assert!(
            error.contains("will not start a second one"),
            "the refusal has to say what it refuses: {error}"
        );
        assert!(
            socket.exists(),
            "the live daemon's endpoint must survive the refusal"
        );

        // The refusal comes from the process, not from the socket: once the process is gone
        // the same run directory gets past this check (and on this host stops at the missing
        // program, which is a different message).
        fake.start_kill().unwrap();
        let _ = fake.wait().await;
        let mut gone = false;
        for _ in 0..100 {
            if live_swtpm_on(&state_dir)
                .expect("this host can read /proc")
                .is_none()
            {
                gone = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(gone, "the fake has to leave the process table");
        let error = match Swtpm::start(&run_dir).await {
            Ok(_) => panic!("`swtpm` is not installed on this host"),
            Err(error) => error.to_string(),
        };
        assert!(
            !error.contains(&format!("pid {pid}")),
            "a gone process is not an owner: {error}"
        );

        drop(listener);
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

    /// The three ways out of the synchronous wait, and the one that was missing.
    #[test]
    fn test_the_synchronous_stop_names_its_exit_its_wait_and_its_kill() {
        let grace = Duration::from_millis(100);
        // A confirmed exit is the end of the wait, whatever the clock says: a child that has
        // already been reaped must not be signalled.
        assert_eq!(
            sync_stop_step(WaitProbe::Exited, Duration::from_secs(60), grace),
            SyncStopStep::Exited
        );
        // Inside the grace the child still gets to flush its state.
        assert_eq!(
            sync_stop_step(WaitProbe::StillRunning, Duration::ZERO, grace),
            SyncStopStep::KeepWaiting
        );
        assert_eq!(
            sync_stop_step(WaitProbe::StillRunning, Duration::from_millis(99), grace),
            SyncStopStep::KeepWaiting
        );
        // At the boundary the grace is over.
        assert_eq!(
            sync_stop_step(WaitProbe::StillRunning, grace, grace),
            SyncStopStep::Kill
        );
        // A probe that failed says nothing about the child, so it is not an exit either.
        assert_eq!(
            sync_stop_step(WaitProbe::Failed, Duration::ZERO, grace),
            SyncStopStep::Kill
        );
    }

    /// A child that ignores `SIGTERM` is killed, and the kill is confirmed.
    ///
    /// The old loop fell out of the wait, sent `SIGKILL` and returned nothing, so `Drop` went on
    /// to remove the run directory - and the TPM state inside it - with no statement about
    /// whether the process was gone.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_the_synchronous_stop_escalates_and_confirms_the_kill() {
        // The trailing loop keeps `sh` as the surviving process: a bare last command would be
        // `exec`ed and inherit the default `SIGTERM` disposition instead of the trap, and the
        // test would then prove the graceful path instead of the escalation.
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
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("sh is available");
        let mut swtpm = Swtpm::from_child(child, PathBuf::from("/nonexistent/swtpm.sock"));
        let grace = Duration::from_millis(150);
        // The marker proves the trap is installed before the signal goes out, otherwise the
        // test races the shell's startup.
        for _ in 0..500 {
            if marker.is_file() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(marker.is_file(), "the trap never got installed");

        let started = Instant::now();
        assert!(
            swtpm.stop_now_within(grace),
            "a killed child is gone, and the stop has to say so"
        );
        let elapsed = started.elapsed();
        assert!(
            elapsed >= grace,
            "the child ignores SIGTERM, so the grace must have run out first: {elapsed:?}"
        );
        assert!(
            swtpm.child.try_wait().expect("try_wait works").is_some(),
            "the child must be reaped, not merely signalled"
        );
    }

    /// A child somebody else already reaped cannot be confirmed gone, so it is not reported so.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_a_stop_that_cannot_confirm_the_exit_says_so() {
        let child = tokio::process::Command::new("bash")
            .arg("-c")
            .arg("sleep 60")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("bash must be on PATH");
        let pid = child.id().expect("a spawned child has a pid");
        let mut swtpm = Swtpm::from_child(child, PathBuf::from("/nonexistent/swtpm.sock"));
        reap_behind_the_handles_back(pid);

        assert!(
            !swtpm.stop_now_within(Duration::from_millis(100)),
            "a child that was reaped behind our back was reported as confirmed stopped"
        );
    }

    /// A timeout says which process was being started and whether it is gone.
    ///
    /// "timed out waiting for the control socket" answered neither question, and the two
    /// answers lead to opposite next steps: a `swtpm` that is still there owns the state
    /// directory - the next start refuses it for that reason - while one that is confirmed
    /// gone leaves the directory free for a retry.
    #[test]
    fn test_a_startup_timeout_says_who_it_could_not_stop() {
        let socket = Path::new("/qlean/runs/abc/swtpm.sock");
        let stopped = startup_timeout_message(socket, Some(4242), true);
        assert!(stopped.contains("pid 4242"), "{stopped}");
        assert!(stopped.contains(socket.to_str().unwrap()), "{stopped}");
        assert!(stopped.contains("confirmed gone"), "{stopped}");
        assert!(!stopped.contains("may still be writing"), "{stopped}");

        let survived = startup_timeout_message(socket, Some(4242), false);
        assert!(survived.contains("pid 4242"), "{survived}");
        assert!(survived.contains("may still be writing"), "{survived}");
        assert!(
            !survived.contains("confirmed gone"),
            "an unconfirmed stop must not be reported as a clean one: {survived}"
        );

        // The pid is optional: `child.id()` is `None` once the child was reaped.
        let unknown = startup_timeout_message(socket, None, false);
        assert!(unknown.contains("the swtpm it started"), "{unknown}");
        assert!(!unknown.contains("pid None"), "{unknown}");
    }

    /// A daemon is asked to terminate before it is killed, on every path.
    ///
    /// `stop` and the startup timeout both end a `swtpm`, and `SIGKILL` is the one way that
    /// costs the guest its TPM identity (a half-written state file). The polite signal has to
    /// land first, and the exit status is what says which signal ended the child: a `sleep`
    /// dies of `SIGTERM` (15) when it is asked, and only an escalation reports `SIGKILL` (9).
    #[cfg(unix)]
    #[tokio::test]
    async fn test_a_daemon_is_asked_to_stop_before_it_is_killed() {
        use std::os::unix::process::ExitStatusExt;

        // Polite first: `sleep` exits on SIGTERM, so a kill-first ladder would report signal 9.
        let mut polite = tokio::process::Command::new("sleep")
            .arg("30")
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("sleep is available");
        let started = Instant::now();
        assert!(
            terminate_and_confirm_within(&mut polite, Duration::from_millis(500)).await,
            "a child that exits on SIGTERM is confirmed gone"
        );
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "the grace period is plenty for a SIGTERM"
        );
        let status = polite
            .try_wait()
            .expect("try_wait works")
            .expect("the child was reaped");
        assert_eq!(
            status.signal(),
            Some(15),
            "the child has to be asked to stop, not killed"
        );

        // Uncooperative: ignores SIGTERM, so the ladder has to escalate and still confirm.
        // The marker says the trap is installed before the signal goes out; without it the
        // test races the shell's startup and the child dies of SIGTERM instead.
        let root = temp_dir("swtpm-terminate-first");
        let installed = root.join("trapped");
        let mut stubborn = tokio::process::Command::new("bash")
            .arg("-c")
            .arg(format!(
                "trap '' TERM; : > {}; while :; do sleep 0.05; done",
                installed.display()
            ))
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("bash must be on PATH");
        for _ in 0..500 {
            if installed.is_file() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(installed.is_file(), "the trap never got installed");
        assert!(
            terminate_and_confirm_within(&mut stubborn, Duration::from_millis(100)).await,
            "the escalation has to end with a reaped child"
        );
        let status = stubborn
            .try_wait()
            .expect("try_wait works")
            .expect("the child was reaped");
        assert_eq!(
            status.signal(),
            Some(9),
            "a child that ignores SIGTERM is killed, and the kill is confirmed"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A stale control socket is removed so the real `swtpm` can bind its own.
    ///
    /// A crashed run leaves the socket file behind and `swtpm` refuses to bind on top of it,
    /// so `start` deletes exactly that entry - it is Qlean's own endpoint - and the TPM has to
    /// come up on the same path. Container evidence only: this needs the real program.
    #[cfg(unix)]
    #[ignore = "needs a real `swtpm` on the host"]
    #[tokio::test]
    async fn test_a_real_swtpm_starts_over_a_stale_control_socket() {
        let run_dir = temp_dir("swtpm-stale-socket");
        let socket = run_dir.join("swtpm.sock");
        {
            let stale = std::os::unix::net::UnixListener::bind(&socket).unwrap();
            drop(stale);
        }
        assert_eq!(
            control_socket_state(&socket).unwrap(),
            ControlSocket::Socket,
            "the fixture has to leave a real socket file behind"
        );

        let mut tpm = match Swtpm::start(&run_dir).await {
            Ok(tpm) => tpm,
            Err(error) => panic!("a real swtpm is required for this test: {error}"),
        };
        assert_eq!(tpm.socket(), socket.as_path());
        assert!(
            control_socket_state(&socket).unwrap().is_socket(),
            "the path has to hold the new swtpm's socket, not the stale one"
        );
        let stopped = tpm.stop().await;
        assert!(stopped, "the real swtpm has to be confirmed gone");
    }

    /// A real `swtpm` owns its state directory, and the next start says so.
    ///
    /// `swtpm` 0.10.2 does not lock `--tpmstate`: measured in the container, two daemons with
    /// the same directory both ran and both wrote `tpm2-00.permall`. Qlean therefore has to
    /// read the owner off the process table itself. Without the check the second `start`
    /// deleted the live daemon's control socket and spawned a second writer of the same state
    /// - on Windows that is a lost TPM identity and a BitLocker recovery prompt.
    ///
    /// Container evidence only: this needs the real program.
    #[cfg(unix)]
    #[ignore = "needs a real `swtpm` on the host"]
    #[tokio::test]
    async fn test_a_real_swtpm_owns_its_state_directory_against_a_second_start() {
        let run_dir = temp_dir("swtpm-owned-state");
        let mut first = match Swtpm::start(&run_dir).await {
            Ok(tpm) => tpm,
            Err(error) => panic!("a real swtpm is required for this test: {error}"),
        };
        let pid = first.child.id().expect("a spawned swtpm has a pid");
        let socket = run_dir.join("swtpm.sock");

        let error = match Swtpm::start(&run_dir).await {
            Ok(_) => panic!("the state directory is being written by pid {pid}"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains(&format!("pid {pid}")),
            "the refusal has to name the running TPM: {error}"
        );
        assert!(
            control_socket_state(&socket).unwrap().is_socket(),
            "the refusal must leave the live daemon's endpoint in place"
        );

        // The first daemon was never touched: it still flushes its state on the way out.
        assert!(
            first.stop().await,
            "the first swtpm has to be confirmed gone"
        );

        // And the run directory is not wedged: with the owner gone, the TPM starts again.
        let mut second = match Swtpm::start(&run_dir).await {
            Ok(tpm) => tpm,
            Err(error) => panic!("a free state directory has to be usable: {error}"),
        };
        assert!(
            control_socket_state(&socket).unwrap().is_socket(),
            "the new daemon binds the same control socket path"
        );
        assert!(
            second.stop().await,
            "the second swtpm has to be confirmed gone"
        );
        let _ = std::fs::remove_dir_all(&run_dir);
    }

    /// Name of the state file a real `swtpm` writes its TPM 2.0 state into.
    const TPM_STATE_FILE: &str = "tpm2-00.permall";

    /// The graceful stop has to reach the real `swtpm`, not just a `sleep`.
    ///
    /// `stop` promises that `swtpm` gets to flush its state, because a `SIGKILL` leaves the
    /// guest without the TPM identity it sealed secrets against (on Windows: BitLocker
    /// recovery prompts). `swtpm` rewrites `tpm2-00.permall` on the way out, so the file
    /// must differ from its startup contents afterwards. A fake child cannot show that;
    /// this needs the real program.
    #[ignore = "needs a real `swtpm` on the host"]
    #[tokio::test]
    async fn test_a_real_swtpm_flushes_its_state_when_it_is_stopped() {
        let run_dir = temp_dir("swtpm-flush");
        let state = run_dir.join("tpm").join(TPM_STATE_FILE);

        let mut tpm = match Swtpm::start(&run_dir).await {
            Ok(tpm) => tpm,
            Err(error) => panic!("a real swtpm is required for this test: {error}"),
        };
        let at_startup = std::fs::read(&state).unwrap_or_else(|error| {
            panic!(
                "swtpm created no state file at {}: {error}",
                state.display()
            )
        });

        assert!(tpm.stop().await, "swtpm must confirm its exit");
        let after_stop = std::fs::read(&state).unwrap_or_else(|error| {
            panic!("swtpm left no state file at {}: {error}", state.display())
        });

        assert_ne!(
            at_startup,
            after_stop,
            "`swtpm` wrote {} bytes at startup and the same {} bytes after the stop: it was \
             killed instead of asked to terminate, so the TPM state was never flushed",
            at_startup.len(),
            after_stop.len()
        );
        let _ = std::fs::remove_dir_all(&run_dir);
    }

    /// Kill `pid` and reap it behind its handle's back, so the handle's own `wait` gets
    /// `ECHILD` - the one `Ok(Err(_))` a test can induce for real.
    fn reap_behind_the_handles_back(pid: u32) {
        let mut status = 0_i32;
        // SAFETY: a positive pid that this process owns; `SIGKILL` and `waitpid` only touch
        // that process's state, and the blocking wait returns as soon as it is gone.
        unsafe {
            libc::kill(pid as libc::pid_t, libc::SIGKILL);
            let reaped = libc::waitpid(pid as libc::pid_t, &mut status, 0);
            assert_eq!(reaped, pid as libc::pid_t, "the child was not reaped");
        }
    }

    /// A `wait` that fails is not an exit: it says nothing about the child.
    #[tokio::test]
    async fn test_a_wait_that_fails_is_not_reported_as_an_exit() {
        let mut child = tokio::process::Command::new("bash")
            .arg("-c")
            .arg("sleep 60")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("bash must be on PATH");
        let pid = child.id().expect("a spawned child has a pid");
        reap_behind_the_handles_back(pid);

        let waited = tokio::time::timeout(SHUTDOWN_GRACE, child.wait()).await;
        match wait_outcome(waited) {
            WaitOutcome::Failed(error) => assert!(
                error.contains("No child processes"),
                "the refusal is kept as it arrived: {error}"
            ),
            other => panic!("a failed wait must not be reported as {other:?}"),
        }
    }

    /// The other two answers: a real exit, and a real grace expiry.
    #[tokio::test]
    async fn test_the_wait_outcome_names_the_exit_the_timeout_and_the_failure() {
        let mut quick = tokio::process::Command::new("bash")
            .arg("-c")
            .arg("exit 3")
            .spawn()
            .expect("bash must be on PATH");
        let status = quick.wait().await.expect("a plain exit");
        assert_eq!(wait_outcome(Ok(Ok(status))), WaitOutcome::Exited);

        let expired = tokio::time::timeout(
            Duration::from_millis(1),
            std::future::pending::<std::io::Result<std::process::ExitStatus>>(),
        )
        .await;
        assert_eq!(wait_outcome(expired), WaitOutcome::TimedOut);
    }

    /// A swtpm nobody could wait for is not a stopped swtpm.
    #[tokio::test]
    async fn test_a_swtpm_that_cannot_be_waited_for_is_not_reported_stopped() {
        let child = tokio::process::Command::new("bash")
            .arg("-c")
            .arg("sleep 60")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("bash must be on PATH");
        let pid = child.id().expect("a spawned child has a pid");
        let mut swtpm = Swtpm::from_child(child, PathBuf::from("/nonexistent/swtpm.sock"));
        // The reaped pid is already gone, so the signal is refused and the wait fails: the
        // TPM state directory is nobody's to rebuild, and `stop` has to say so.
        reap_behind_the_handles_back(pid);
        assert!(
            !swtpm.stop().await,
            "a swtpm whose wait failed must not be reported as confirmed stopped"
        );
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
        assert!(
            tokio::time::timeout(Duration::from_secs(20), swtpm.stop())
                .await
                .expect("stop must finish"),
            "a killed swtpm is only stopped once it is reaped"
        );
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

    /// A host with nothing installed: every gap is reported, in the order the machine hits it.
    fn bare_host_fixture() -> HostProbes<'static> {
        HostProbes {
            qemu_img: Presence::Missing,
            qemu_system: Presence::Missing,
            kvm_available: false,
            ovmf: Err(anyhow::anyhow!("no OVMF firmware found")),
            swtpm: Path::new("swtpm"),
            swtpm_presence: Presence::Missing,
            seed_iso_builder: Presence::Missing,
            virsh: Presence::Missing,
        }
    }

    /// A host that provides everything the Windows guest path needs.
    fn complete_host_fixture() -> HostProbes<'static> {
        HostProbes {
            qemu_img: Presence::Ready,
            qemu_system: Presence::Ready,
            kvm_available: true,
            ovmf: Ok(firmware_fixture()),
            swtpm: Path::new("swtpm"),
            swtpm_presence: Presence::Ready,
            seed_iso_builder: Presence::Ready,
            virsh: Presence::Ready,
        }
    }

    /// Find the one gap that mentions `needle`, failing loudly if it is absent.
    fn gap<'a>(problems: &'a [String], needle: &str) -> &'a str {
        problems
            .iter()
            .find(|problem| problem.contains(needle))
            .unwrap_or_else(|| panic!("no gap mentions {needle:?}: {problems:?}"))
    }

    #[test]
    fn test_host_support_reports_every_gap_at_once() {
        let problems = host_support_problems(bare_host_fixture());

        // Every missing piece, including the two programs that run before QEMU: a bare host
        // must not learn about `qemu-img` from an unrelated failure first and about
        // `qemu-system-x86_64` only after reinstalling.
        assert_eq!(problems.len(), 7, "gaps: {problems:?}");
        assert!(
            gap(&problems, "`qemu-img` was not found").contains("overlay"),
            "the qemu-img gap must say what it is for: {problems:?}"
        );
        assert!(
            gap(&problems, "`qemu-system-x86_64` was not found").contains("runs under"),
            "the qemu-system gap must say what it is for: {problems:?}"
        );
        assert_eq!(
            problems[2],
            "KVM acceleration is unavailable: Windows guests require KVM and never fall back to TCG"
        );
        assert!(gap(&problems, "no OVMF firmware found") == problems[3]);
        let swtpm = gap(&problems, "install the `swtpm` package");
        assert!(swtpm.contains(ENV_SWTPM), "{swtpm}");
        assert!(gap(&problems, "install the `xorriso` package").contains("seed medium"));
        let virsh = gap(&problems, "install the `libvirt` package");
        assert!(virsh.contains("net-dhcp-leases"), "{virsh}");

        // The aggregated error keeps every line, so one run lists all seven gaps.
        let message = format!(
            "Windows guest prerequisites are missing:\n- {}",
            problems.join("\n- ")
        );
        assert_eq!(message.lines().count(), 8, "{message}");
    }

    /// The gaps come out in the order the README's prerequisite table lists them.
    ///
    /// R234 made the README say the table runs "in the order of this table" == the order the
    /// gate reports. Only two of the seven positions were pinned - `problems[2]` and
    /// `problems[3]` - and the other five could be swapped with the whole suite green, which
    /// would leave a promise describing a message that no longer exists. The order is one fact
    /// with two descriptions again, so the two are compared here instead of both being trusted:
    /// each reported gap is identified by the name it carries, and the sequence has to be the
    /// shared list from `crate::plan_doc_tests`.
    #[test]
    fn test_host_support_lists_the_gaps_in_the_readmes_order() {
        let problems = host_support_problems(bare_host_fixture());
        let mut reported: Vec<&str> = Vec::new();
        for problem in &problems {
            // Exactly one, so a message that named two gaps cannot pass by naming the right one
            // twice: "one problem per gap" is what makes a sequence of them meaningful.
            let named: Vec<&str> = crate::plan_doc_tests::WINDOWS_PREREQUISITE_GAPS
                .into_iter()
                .filter(|gap| problem.contains(gap))
                .collect();
            assert_eq!(
                named.len(),
                1,
                "this gap names {named:?}, so the reported order cannot be read: {problem:?}"
            );
            reported.push(named[0]);
        }
        assert_eq!(
            reported,
            crate::plan_doc_tests::WINDOWS_PREREQUISITE_GAPS.to_vec(),
            "the gate reports the gaps in a different order than the README's table, which now \
             promises to be the order of this message"
        );
    }

    #[test]
    fn test_host_support_is_quiet_when_everything_is_present() {
        let problems = host_support_problems(complete_host_fixture());

        assert!(problems.is_empty(), "unexpected gaps: {problems:?}");
    }

    #[test]
    fn test_host_support_reports_only_the_missing_piece() {
        let problems = host_support_problems(HostProbes {
            seed_iso_builder: Presence::Missing,
            ..complete_host_fixture()
        });
        assert_eq!(problems.len(), 1, "gaps: {problems:?}");
        assert!(
            problems[0].contains("`xorriso` was not found"),
            "{problems:?}"
        );

        let problems = host_support_problems(HostProbes {
            swtpm_presence: Presence::Missing,
            swtpm: Path::new("/opt/swtpm"),
            ..complete_host_fixture()
        });
        assert_eq!(problems.len(), 1, "gaps: {problems:?}");
        assert!(problems[0].contains("/opt/swtpm"), "{problems:?}");

        let problems = host_support_problems(HostProbes {
            virsh: Presence::Missing,
            ..complete_host_fixture()
        });
        assert_eq!(problems.len(), 1, "gaps: {problems:?}");
        assert!(
            problems[0].contains("`virsh` was not found"),
            "{problems:?}"
        );

        // The two programs the machine runs first are reported on their own as well, so a
        // host that only lacks one of them still gets that one sentence.
        let problems = host_support_problems(HostProbes {
            qemu_img: Presence::Missing,
            ..complete_host_fixture()
        });
        assert_eq!(problems.len(), 1, "gaps: {problems:?}");
        assert!(
            problems[0].contains("`qemu-img` was not found"),
            "{problems:?}"
        );

        let problems = host_support_problems(HostProbes {
            qemu_system: Presence::Missing,
            ..complete_host_fixture()
        });
        assert_eq!(problems.len(), 1, "gaps: {problems:?}");
        assert!(
            problems[0].contains("`qemu-system-x86_64` was not found"),
            "{problems:?}"
        );
        assert!(INSTALL_HINT.contains("edk2-ovmf"));
        assert!(INSTALL_HINT.contains("QLEAN_OVMF_CODE"));
    }

    /// A program that is there but cannot be executed is a gap, and named as that gap.
    ///
    /// `command_available` asked only `is_file`, so a `swtpm` whose mode lost its executable
    /// bit (a tarball unpacked elsewhere, a backup restored by hand, a `noexec` mount) passed
    /// the gate whose whole purpose is to name every gap at the cheapest moment. The failure
    /// then arrived from inside `launch` as `Permission denied (os error 13)` with no program
    /// name in it. Probed here: the file exists, `Command::new` on it fails with `EACCES`.
    #[test]
    fn test_a_program_that_cannot_be_executed_is_a_gap_of_its_own() {
        let root = temp_dir("r214-nonexecutable-program");
        let swtpm = root.join("swtpm");
        std::fs::write(&swtpm, b"#!/bin/sh\nexit 0\n").expect("write");
        let mode = |path: &Path, mode: u32| {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = std::fs::metadata(path).expect("stat").permissions();
            permissions.set_mode(mode);
            std::fs::set_permissions(path, permissions).expect("chmod");
        };
        mode(&swtpm, 0o644);

        // What the host does with it, so the verdict below is about a real inability.
        let spawned = std::process::Command::new(&swtpm).arg("--version").status();
        let refusal = match &spawned {
            Ok(_) => None,
            Err(error) => Some(error.kind()),
        };
        assert_eq!(
            refusal,
            Some(std::io::ErrorKind::PermissionDenied),
            "a file without the executable bit must not run: {spawned:?}"
        );

        assert_eq!(
            program_presence(&swtpm),
            Presence::NotExecutable(swtpm.clone()),
            "a file that cannot be executed is not `Ready`"
        );
        assert_eq!(program_presence(&root.join("absent")), Presence::Missing);

        let problems = host_support_problems(HostProbes {
            swtpm_presence: program_presence(&swtpm),
            swtpm: &swtpm,
            ..complete_host_fixture()
        });
        assert_eq!(problems.len(), 1, "gaps: {problems:?}");
        assert!(
            problems[0].contains("cannot be executed") && problems[0].contains("swtpm"),
            "the gap has to say it cannot run, not that it is absent: {problems:?}"
        );
        // A `swtpm` given by path is named by that path, so the sentence above cannot show
        // whether the *location* travels with the message. The next case asks that of a
        // program the gate knows by a fixed name: the file has to be named separately, or the
        // user is told to fix a `qemu-img` whose permissions they cannot find.
        let qemu_img = root.join("qemu-img");
        std::fs::write(&qemu_img, b"#!/bin/sh\nexit 0\n").expect("write");
        mode(&qemu_img, 0o644);
        let problems = host_support_problems(HostProbes {
            qemu_img: program_presence(&qemu_img),
            ..complete_host_fixture()
        });
        assert_eq!(problems.len(), 1, "gaps: {problems:?}");
        assert!(
            problems[0].contains("`qemu-img`") && problems[0].contains("cannot be executed"),
            "the qemu-img gap has to keep the program name it is filed under: {problems:?}"
        );
        assert!(
            problems[0].contains(&qemu_img.display().to_string()),
            "the gap has to name the file whose permissions are wrong: {problems:?}"
        );
        assert!(
            !problems[0].contains("was not found"),
            "`qemu-img` is installed; `not found` is the wrong repair: {problems:?}"
        );
        assert!(
            !problems[0].contains("was not found"),
            "the file is there; `not found` sends the user to install what they already have: \
             {problems:?}"
        );

        // The executable bit is what decides, not the name or the size.
        mode(&swtpm, 0o755);
        assert_eq!(program_presence(&swtpm), Presence::Ready);
        assert!(
            host_support_problems(HostProbes {
                swtpm_presence: program_presence(&swtpm),
                swtpm: &swtpm,
                ..complete_host_fixture()
            })
            .is_empty(),
            "the same file becomes usable once it can be executed"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_program_presence_checks_absolute_paths() {
        assert_eq!(program_presence(Path::new("/bin/sh")), Presence::Ready);
        assert_eq!(
            program_presence(Path::new("/definitely/not/a/binary")),
            Presence::Missing
        );
        // A directory is not a program, whatever its mode says.
        assert_eq!(program_presence(Path::new("/bin")), Presence::Missing);
    }
}
