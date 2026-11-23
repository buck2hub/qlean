//! OrbStack host gate for macOS.
//!
//! Command spelling lives here. Unit tests inject the lookup and the status
//! text, so they never spawn `orb`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::utils::{bounded_output, is_executable_file};

/// How long `orb status` may take before the probe gives up.
const STATUS_BUDGET: Duration = Duration::from_secs(5);

/// Text returned when the `orb` binary is not on `PATH`.
pub(crate) fn missing_orbstack_message() -> &'static str {
    "Qlean on macOS needs OrbStack. Install it with `brew install orbstack`, start OrbStack, and retry. Installing QEMU on the Mac is not the fix."
}

/// Where `orb` was found, if anywhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OrbLocation {
    /// No file named `orb` on `PATH`.
    Missing,
    /// A file named `orb` exists, but the host cannot execute it.
    NotExecutable { path: PathBuf },
    /// An executable `orb` is on `PATH`.
    Found { path: PathBuf },
}

/// Decide whether OrbStack can be used, from an injected lookup and status.
///
/// `status` is the stdout of `orb status`, or the error string when that
/// command could not be run. It is ignored unless `location` is [`OrbLocation::Found`].
pub(crate) fn classify_orb(location: &OrbLocation, status: Result<&str, &str>) -> Result<()> {
    match location {
        OrbLocation::Missing => bail!("{}", missing_orbstack_message()),
        OrbLocation::NotExecutable { path } => bail!(
            "OrbStack's `orb` is at {} but cannot be executed. Fix the file mode or remount that filesystem without `noexec`, then retry.",
            path.display()
        ),
        OrbLocation::Found { .. } => match status {
            Ok(text) if text.trim() == "Running" => Ok(()),
            Ok(text) => {
                let summary = one_line(text);
                bail!(
                    "OrbStack is installed but not running. Start OrbStack (`orb`, or `orb start` if the app is stopped). `orb status` should print `Running`. The probe returned: {summary}"
                )
            }
            Err(error) => {
                let summary = one_line(error);
                bail!(
                    "OrbStack is installed but not running. Start OrbStack (`orb`, or `orb start` if the app is stopped). `orb status` should print `Running`. The probe failed: {summary}"
                )
            }
        },
    }
}

/// Look up `orb` on `PATH` and ask `orb status`, with a timeout.
pub(crate) async fn ensure_orbstack() -> Result<()> {
    let location = locate_orb();
    let status = match &location {
        OrbLocation::Found { path } => run_status(path).await,
        _ => Err(String::new()),
    };
    let status_ref = match &status {
        Ok(text) => Ok(text.as_str()),
        Err(error) => Err(error.as_str()),
    };
    classify_orb(&location, status_ref)
}

fn one_line(text: &str) -> String {
    let mut line = text.split_whitespace().collect::<Vec<_>>().join(" ");
    const LIMIT: usize = 120;
    if line.len() > LIMIT {
        line.truncate(LIMIT);
        line.push('…');
    }
    if line.is_empty() {
        "(empty)".to_string()
    } else {
        line
    }
}

fn locate_orb() -> OrbLocation {
    let Some(paths) = std::env::var_os("PATH") else {
        return OrbLocation::Missing;
    };
    let mut unusable: Option<PathBuf> = None;
    for dir in std::env::split_paths(&paths) {
        let candidate = dir.join("orb");
        if is_executable_file(&candidate) {
            return OrbLocation::Found { path: candidate };
        }
        if unusable.is_none() && candidate.is_file() {
            unusable = Some(candidate);
        }
    }
    match unusable {
        Some(path) => OrbLocation::NotExecutable { path },
        None => OrbLocation::Missing,
    }
}

async fn run_status(program: &Path) -> Result<String, String> {
    let mut command = tokio::process::Command::new(program);
    command.arg("status");
    match bounded_output(command, STATUS_BUDGET, "ask OrbStack whether it is running").await {
        Ok(output) if output.status.success() => {
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        }
        Ok(output) => Err(format!(
            "exit {}: {}",
            output.status,
            one_line(&String::from_utf8_lossy(&output.stderr))
        )),
        Err(error) => Err(format!("{error:#}")),
    }
}

/// Localhost SSH port recorded by MAC-00.
pub(crate) const SSH_PORT: u16 = 32222;

/// Host OrbStack's SSH service binds.
pub(crate) const SSH_HOST: &str = "127.0.0.1";

const MACHINE_PREFIX: &str = "qlean-";

/// OrbStack rejects `--memory` below 1 GiB. `MachineConfig.mem` is MiB.
pub(crate) const MIN_MEMORY_MIB: u32 = 1024;

/// One `orb` invocation's captured text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommandResult {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Process execution the lifecycle calls. Tests supply a script instead of `orb`.
pub(crate) trait OrbExec {
    fn execute(
        &mut self,
        args: &[String],
    ) -> impl std::future::Future<Output = Result<CommandResult>> + Send;
}

/// Runs the real `orb` binary.
pub(crate) struct LiveOrb;

impl OrbExec for LiveOrb {
    async fn execute(&mut self, args: &[String]) -> Result<CommandResult> {
        let budget = if args.first().is_some_and(|arg| arg == "create") {
            Duration::from_secs(600)
        } else {
            Duration::from_secs(60)
        };
        let mut command = tokio::process::Command::new("orb");
        command.args(args);
        let output = bounded_output(command, budget, "run orb").await?;
        Ok(CommandResult {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

/// A machine name is `qlean-` plus the 12 hex digits of its id, or an error.
pub(crate) fn machine_name(id: &str) -> Result<String> {
    if is_machine_id(id) {
        Ok(format!("{MACHINE_PREFIX}{id}"))
    } else {
        bail!(
            "OrbStack machine name must be `{MACHINE_PREFIX}` plus 12 hexadecimal digits, got {id:?}"
        )
    }
}

/// Whether `name` is exactly `qlean-` plus 12 hexadecimal digits.
pub(crate) fn is_managed_name(name: &str) -> bool {
    let Some(id) = name.strip_prefix(MACHINE_PREFIX) else {
        return false;
    };
    is_machine_id(id)
}

fn is_machine_id(id: &str) -> bool {
    id.len() == 12 && id.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Stop and delete refuse a name that is not one of ours.
pub(crate) fn require_managed_name(name: &str) -> Result<()> {
    if is_managed_name(name) {
        Ok(())
    } else {
        bail!(
            "refusing to control OrbStack machine {name:?}: only `{MACHINE_PREFIX}` plus 12 hexadecimal digits is managed"
        )
    }
}

/// The sentence init logs for the memory and disk it will pass to `orb create`.
pub(crate) fn resource_log(mem_mib: u32, disk_gb: Option<u32>) -> String {
    match disk_gb {
        Some(disk) => {
            format!("OrbStack machine resources: --memory {mem_mib} (MiB) --disk {disk}G")
        }
        None => format!("OrbStack machine resources: --memory {mem_mib} (MiB)"),
    }
}

/// `--arch` value for this host, or an error that does not prescribe installing KVM.
pub(crate) fn arch_flag(host_aarch64: bool, arch: crate::GuestArch) -> Result<&'static str> {
    use crate::GuestArch;
    match arch {
        GuestArch::Amd64 => Ok("amd64"),
        GuestArch::Aarch64 if host_aarch64 => Ok("arm64"),
        GuestArch::Aarch64 => bail!(
            "Creating an aarch64 OrbStack machine on an Intel Mac was not tested, so Qlean refuses it. OrbStack's flag is `arm64` or `amd64`, not `aarch64`."
        ),
        GuestArch::Riscv64 => {
            bail!("Riscv64 guests are not available on OrbStack. Its machines are arm64 and amd64.")
        }
    }
}

/// Bare distro name. OrbStack picks its default stable version.
pub(crate) fn distro_arg(distro: crate::Distro) -> &'static str {
    use crate::Distro;
    match distro {
        Distro::Debian => "debian",
        Distro::Ubuntu => "ubuntu",
        Distro::Fedora => "fedora",
        Distro::Arch => "arch",
    }
}

/// Reject guests this plan does not run on macOS.
pub(crate) fn require_supported_guest(
    guest_os: crate::GuestOs,
    arch: crate::GuestArch,
    has_source: bool,
    host_aarch64: bool,
) -> Result<()> {
    use crate::GuestOs;
    if guest_os == GuestOs::Windows {
        bail!(
            "Windows guests are not available on macOS. OrbStack has no Windows machines. This is not fixed by installing QEMU on the Mac."
        );
    }
    if has_source {
        bail!(
            "Custom qcow2 images are not supported on macOS. OrbStack machines use its built-in distros, not a caller-supplied image."
        );
    }
    arch_flag(host_aarch64, arch)?;
    Ok(())
}

/// `orb create` arguments. Does not include the program name.
pub(crate) fn create_args(
    distro: crate::Distro,
    arch: crate::GuestArch,
    host_aarch64: bool,
    cpus: u32,
    mem_mib: u32,
    disk_gb: Option<u32>,
    name: &str,
) -> Result<Vec<String>> {
    require_managed_name(name)?;
    if mem_mib < MIN_MEMORY_MIB {
        bail!(
            "OrbStack memory must be at least {MIN_MEMORY_MIB} MiB, got {mem_mib}. `--memory` is MiB and OrbStack rejects anything under 1 GiB."
        );
    }
    let arch_value = arch_flag(host_aarch64, arch)?;
    tracing::info!("{}", resource_log(mem_mib, disk_gb));
    let mut args = vec![
        "create".to_string(),
        "--isolated".to_string(),
        "--cpus".to_string(),
        cpus.to_string(),
        "--memory".to_string(),
        mem_mib.to_string(),
        "--arch".to_string(),
        arch_value.to_string(),
    ];
    if let Some(disk) = disk_gb {
        args.push("--disk".to_string());
        args.push(format!("{disk}G"));
    }
    args.push(distro_arg(distro).to_string());
    args.push(name.to_string());
    Ok(args)
}

pub(crate) fn start_args(name: &str) -> Result<Vec<String>> {
    require_managed_name(name)?;
    Ok(vec!["start".to_string(), name.to_string()])
}

pub(crate) fn stop_args(name: &str) -> Result<Vec<String>> {
    require_managed_name(name)?;
    Ok(vec!["stop".to_string(), name.to_string()])
}

pub(crate) fn delete_args(name: &str) -> Result<Vec<String>> {
    require_managed_name(name)?;
    Ok(vec![
        "delete".to_string(),
        "-f".to_string(),
        name.to_string(),
    ])
}

pub(crate) fn list_args() -> Vec<String> {
    vec!["list".to_string(), "-f".to_string(), "json".to_string()]
}

pub(crate) fn info_args(name: &str) -> Result<Vec<String>> {
    require_managed_name(name)?;
    Ok(vec![
        "info".to_string(),
        name.to_string(),
        "-f".to_string(),
        "json".to_string(),
    ])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ListedMachine {
    pub name: String,
    pub state: String,
}

pub(crate) fn parse_list(stdout: &str) -> Result<Vec<ListedMachine>> {
    let value: serde_json::Value = serde_json::from_str(stdout)
        .with_context(|| format!("orb list did not return JSON: {}", one_line(stdout)))?;
    let Some(items) = value.as_array() else {
        bail!("orb list JSON was not an array: {}", one_line(stdout));
    };
    let mut machines = Vec::new();
    for item in items {
        let Some(name) = item.get("name").and_then(|name| name.as_str()) else {
            continue;
        };
        let state = item
            .get("state")
            .and_then(|state| state.as_str())
            .unwrap_or("")
            .to_string();
        machines.push(ListedMachine {
            name: name.to_string(),
            state,
        });
    }
    Ok(machines)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OrbPower {
    Running,
    Stopped,
    Absent,
}

/// IPv4 from `orb info -f json`. This is the host-side address, not `hostname -I`.
pub(crate) fn parse_ip4(name: &str, stdout: &str, command_ok: bool) -> Result<String> {
    let summary = one_line(stdout);
    if !command_ok {
        bail!("could not read the OrbStack address of {name}: {summary}");
    }
    let value: serde_json::Value = serde_json::from_str(stdout)
        .map_err(|_| anyhow::anyhow!("could not read the OrbStack address of {name}: {summary}"))?;
    match value.get("ip4").and_then(|ip| ip.as_str()) {
        Some(ip) if ip.split('.').count() == 4 && ip.split('.').all(is_ipv4_octet) => {
            Ok(ip.to_string())
        }
        _ => bail!("could not read the OrbStack address of {name}: {summary}"),
    }
}

fn is_ipv4_octet(part: &str) -> bool {
    part.parse::<u8>().is_ok() && !(part.len() > 1 && part.starts_with('0'))
}

/// `running` and `stopped` are answers. A probe failure is an error that names the machine.
pub(crate) fn parse_power(name: &str, stdout: &str, command_ok: bool) -> Result<OrbPower> {
    if !command_ok {
        let summary = one_line(stdout);
        if summary.contains("machine not found") {
            return Ok(OrbPower::Absent);
        }
        bail!("could not tell whether OrbStack machine {name} is running: {summary}");
    }
    let value: serde_json::Value = match serde_json::from_str(stdout) {
        Ok(value) => value,
        Err(_) => {
            let summary = one_line(stdout);
            if summary.contains("machine not found") {
                return Ok(OrbPower::Absent);
            }
            bail!("could not tell whether OrbStack machine {name} is running: {summary}");
        }
    };
    let state = value
        .get("record")
        .and_then(|record| record.get("state"))
        .and_then(|state| state.as_str())
        .unwrap_or("");
    match state {
        "running" => Ok(OrbPower::Running),
        "stopped" => Ok(OrbPower::Stopped),
        _ => bail!(
            "could not tell whether OrbStack machine {name} is running: {}",
            one_line(stdout)
        ),
    }
}

/// Names to delete: exact `qlean-` + 12 hex whose run directory is already gone.
pub(crate) fn sweep_names<'a>(
    names: impl IntoIterator<Item = &'a str>,
    run_dir_exists: impl Fn(&str) -> bool,
) -> Vec<String> {
    let mut doomed = Vec::new();
    for name in names {
        if !is_managed_name(name) {
            continue;
        }
        let id = name.trim_start_matches(MACHINE_PREFIX);
        if !run_dir_exists(id) {
            doomed.push(name.to_string());
        }
    }
    doomed
}

/// Create the machine, or start it when that name already exists.
///
/// Returns whether this call created it. A failed create deletes the name only
/// when the list shows it appeared. A failed start of an existing machine does not delete it.
pub(crate) async fn drive_init(
    exec: &mut impl OrbExec,
    name: &str,
    create: &[String],
) -> Result<bool> {
    require_managed_name(name)?;
    let listed = run_ok(exec, &list_args(), "list OrbStack machines").await?;
    let machines = parse_list(&listed)?;
    if machines.iter().any(|machine| machine.name == name) {
        let start = start_args(name)?;
        let result = exec.execute(&start).await?;
        if !result.success {
            bail!(
                "orb start {name} failed: {}",
                one_line(&format!("{} {}", result.stdout, result.stderr))
            );
        }
        return Ok(false);
    }
    let created = exec.execute(create).await?;
    if created.success {
        return Ok(true);
    }
    let cleanup_error = match delete_if_present(exec, name).await {
        Ok(()) => None,
        Err(error) => Some(format!("{error:#}")),
    };
    let create_error = one_line(&format!("{} {}", created.stdout, created.stderr));
    match cleanup_error {
        None => bail!("orb create {name} failed: {create_error}"),
        Some(cleanup) => {
            bail!("orb create {name} failed: {create_error}. Cleanup also failed: {cleanup}")
        }
    }
}

/// Stop, and delete only when `created_this_attempt` is set.
pub(crate) async fn drive_failure(
    exec: &mut impl OrbExec,
    name: &str,
    created_this_attempt: bool,
) -> Result<()> {
    let stop = stop_args(name)?;
    let stopped = exec.execute(&stop).await?;
    if !created_this_attempt {
        if stopped.success {
            return Ok(());
        }
        bail!(
            "orb stop {name} failed: {}",
            one_line(&format!("{} {}", stopped.stdout, stopped.stderr))
        );
    }
    let deleted = exec.execute(&delete_args(name)?).await?;
    if deleted.success {
        return Ok(());
    }
    bail!(
        "orb delete {name} after a failed start failed: {}. stop said: {}",
        one_line(&format!("{} {}", deleted.stdout, deleted.stderr)),
        one_line(&format!("{} {}", stopped.stdout, stopped.stderr))
    )
}

/// `orb stop <name>` and nothing else.
pub(crate) async fn drive_shutdown(exec: &mut impl OrbExec, name: &str) -> Result<()> {
    let stop = stop_args(name)?;
    let result = exec.execute(&stop).await?;
    if result.success {
        return Ok(());
    }
    bail!(
        "orb stop {name} failed: {}",
        one_line(&format!("{} {}", result.stdout, result.stderr))
    )
}

async fn delete_if_present(exec: &mut impl OrbExec, name: &str) -> Result<()> {
    let listed = run_ok(
        exec,
        &list_args(),
        "list OrbStack machines after a failed create",
    )
    .await?;
    let machines = parse_list(&listed)?;
    if !machines.iter().any(|machine| machine.name == name) {
        return Ok(());
    }
    let result = exec.execute(&delete_args(name)?).await?;
    if result.success {
        Ok(())
    } else {
        bail!(
            "{}",
            one_line(&format!("{} {}", result.stdout, result.stderr))
        )
    }
}

async fn run_ok(exec: &mut impl OrbExec, args: &[String], what: &str) -> Result<String> {
    let result = exec.execute(args).await?;
    if result.success {
        Ok(result.stdout)
    } else {
        bail!(
            "{what} failed: {}",
            one_line(&format!("{} {}", result.stdout, result.stderr))
        )
    }
}

/// SSH user, host, port, and private-key path for one machine.
pub(crate) struct SshEndpoint {
    pub host: &'static str,
    pub port: u16,
    pub user: String,
    pub key_path: PathBuf,
}

pub(crate) fn ssh_endpoint(name: &str, home: &Path) -> Result<SshEndpoint> {
    require_managed_name(name)?;
    Ok(SshEndpoint {
        host: SSH_HOST,
        port: SSH_PORT,
        user: format!("root@{name}"),
        key_path: home.join(".orbstack/ssh/id_ed25519"),
    })
}

pub(crate) fn known_hosts_path(home: &Path) -> PathBuf {
    home.join(".orbstack/ssh/known_hosts")
}

/// Read the private key. The error names the path and says not to edit `authorized_keys`.
pub(crate) fn read_private_key(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).with_context(|| {
        format!(
            "OrbStack SSH private key is missing at {}. Do not edit ~/.orbstack/ssh/authorized_keys.",
            display_orb_path(path)
        )
    })
}

pub(crate) fn display_orb_path(path: &Path) -> String {
    let text = path.to_string_lossy();
    if let Some(tail) = text.find(".orbstack/") {
        format!("~/{}", &text[tail..])
    } else {
        text.into_owned()
    }
}

/// The `ssh-ed25519` key OrbStack published for `[127.0.0.1]:32222`.
pub(crate) fn pinned_host_key(known_hosts: &str) -> Result<russh::keys::PublicKey> {
    for line in known_hosts.lines() {
        let mut parts = line.split_whitespace();
        let host = parts.next().unwrap_or("");
        let kind = parts.next().unwrap_or("");
        let key = parts.next().unwrap_or("");
        if host == "[127.0.0.1]:32222" && kind == "ssh-ed25519" && !key.is_empty() {
            return russh::keys::PublicKey::from_openssh(&format!("{kind} {key}")).with_context(
                || "OrbStack known_hosts has an ssh-ed25519 line that is not a public key",
            );
        }
    }
    bail!(
        "OrbStack SSH known_hosts has no ssh-ed25519 key for [127.0.0.1]:32222. Do not edit ~/.orbstack/ssh/authorized_keys."
    )
}

#[cfg(test)]
mod orbstack_prerequisite {
    use super::{OrbLocation, classify_orb, missing_orbstack_message};

    fn assert_no_qemu_install(message: &str) {
        let lower = message.to_ascii_lowercase();
        assert!(
            !lower.contains("install qemu") && !lower.contains("brew install qemu"),
            "{message}"
        );
    }

    #[test]
    fn a_missing_binary_names_orbstack_and_brew() {
        let error = classify_orb(&OrbLocation::Missing, Ok("Running")).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("OrbStack"), "{message}");
        assert!(message.contains("brew install orbstack"), "{message}");
        assert_eq!(missing_orbstack_message(), message);
        assert_no_qemu_install(&message);
    }

    #[test]
    fn an_unexecutable_binary_names_the_path_and_noexec() {
        let error = classify_orb(
            &OrbLocation::NotExecutable {
                path: "/usr/local/bin/orb".into(),
            },
            Ok("Running"),
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("/usr/local/bin/orb"), "{message}");
        assert!(message.contains("noexec"), "{message}");
        assert!(message.contains("OrbStack"), "{message}");
        assert_no_qemu_install(&message);
    }

    #[test]
    fn a_stopped_runtime_is_not_the_install_error() {
        let error = classify_orb(
            &OrbLocation::Found {
                path: "/usr/local/bin/orb".into(),
            },
            Ok("Stopped"),
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("not running"), "{message}");
        assert!(message.contains("orb start"), "{message}");
        assert!(!message.contains("brew install orbstack"), "{message}");
        assert_no_qemu_install(&message);
    }

    #[test]
    fn a_failed_status_probe_is_its_own_error() {
        let error = classify_orb(
            &OrbLocation::Found {
                path: "/usr/local/bin/orb".into(),
            },
            Err("timed out"),
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("not running"), "{message}");
        assert!(message.contains("timed out"), "{message}");
        assert_no_qemu_install(&message);
    }

    #[test]
    fn a_running_status_is_ready_and_creates_nothing() {
        classify_orb(
            &OrbLocation::Found {
                path: "/usr/local/bin/orb".into(),
            },
            Ok("Running\n"),
        )
        .expect("Running is the ready status");
    }
}

#[cfg(test)]
mod orb_create_args {
    use super::{
        arch_flag, create_args, delete_args, distro_arg, is_managed_name, machine_name,
        require_supported_guest, resource_log, start_args, stop_args,
    };
    use crate::{Distro, GuestArch, GuestOs};

    const ID: &str = "00a11e000001";

    fn name() -> String {
        machine_name(ID).unwrap()
    }

    #[test]
    fn distros_use_orbstack_names_without_a_version_pin() {
        assert_eq!(distro_arg(Distro::Debian), "debian");
        assert_eq!(distro_arg(Distro::Ubuntu), "ubuntu");
        assert_eq!(distro_arg(Distro::Fedora), "fedora");
        assert_eq!(distro_arg(Distro::Arch), "arch");
    }

    #[test]
    fn create_uses_isolated_machines_and_the_measured_units() {
        let args = create_args(
            Distro::Debian,
            GuestArch::Amd64,
            true,
            2,
            2048,
            Some(8),
            &name(),
        )
        .unwrap();
        assert!(args.contains(&"--isolated".to_string()), "{args:?}");
        assert!(
            !args.iter().any(|arg| arg == "--isolate-network"),
            "{args:?}"
        );
        assert!(
            !args.iter().any(|arg| arg == "--forward-ssh-agent"),
            "{args:?}"
        );
        assert!(
            args.windows(2).any(|pair| pair == ["--memory", "2048"]),
            "{args:?}"
        );
        assert!(
            args.windows(2).any(|pair| pair == ["--disk", "8G"]),
            "{args:?}"
        );
        assert!(
            args.windows(2).any(|pair| pair == ["--arch", "amd64"]),
            "{args:?}"
        );
        assert_eq!(args.last().unwrap(), &name());
        assert!(resource_log(2048, Some(8)).contains("--memory 2048 (MiB)"));
    }

    #[test]
    fn apple_silicon_aarch64_is_arm64_and_intel_aarch64_is_refused() {
        assert_eq!(arch_flag(true, GuestArch::Aarch64).unwrap(), "arm64");
        let error = arch_flag(false, GuestArch::Aarch64).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("not tested"), "{message}");
        assert!(
            !message.to_ascii_lowercase().contains("install kvm"),
            "{message}"
        );
    }

    #[test]
    fn riscv_windows_and_custom_images_are_refused_without_prescribing_kvm() {
        for error in [
            require_supported_guest(GuestOs::Linux, GuestArch::Riscv64, false, true).unwrap_err(),
            require_supported_guest(GuestOs::Windows, GuestArch::Amd64, true, true).unwrap_err(),
            require_supported_guest(GuestOs::Linux, GuestArch::Amd64, true, true).unwrap_err(),
        ] {
            let message = format!("{error:#}");
            assert!(
                !message.contains("安装 KVM")
                    && !message.to_ascii_lowercase().contains("install kvm"),
                "{message}"
            );
        }
    }

    #[test]
    fn memory_under_one_gib_is_rejected_before_orb_is_called() {
        let error = create_args(
            Distro::Debian,
            GuestArch::Amd64,
            true,
            1,
            512,
            None,
            &name(),
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("1024"), "{message}");
    }

    #[test]
    fn stop_and_delete_reject_a_name_that_is_not_qlean_plus_12_hex() {
        assert!(is_managed_name("qlean-00a11e000001"));
        assert!(!is_managed_name("qlean-00a11e00000"));
        assert!(!is_managed_name("qlean-00a11e0000011"));
        assert!(!is_managed_name("clean-00a11e000001"));
        assert!(!is_managed_name("ubuntu"));
        let error = stop_args("ubuntu").unwrap_err();
        assert!(format!("{error:#}").contains("12 hexadecimal"));
        assert!(delete_args("qlean-00a11e00000g").is_err());
        assert_eq!(
            start_args("qlean-00a11e000001").unwrap(),
            vec!["start".to_string(), "qlean-00a11e000001".to_string()]
        );
    }
}

#[cfg(test)]
mod orb_lifecycle {
    use anyhow::Result;

    use super::{
        CommandResult, OrbExec, OrbPower, create_args, drive_failure, drive_init, drive_shutdown,
        list_args, parse_power, sweep_names,
    };
    use crate::{Distro, GuestArch};

    const NAME: &str = "qlean-00a11e000001";

    struct Script {
        replies: Vec<CommandResult>,
        calls: Vec<Vec<String>>,
    }

    impl Script {
        fn ok(stdout: &str) -> CommandResult {
            CommandResult {
                success: true,
                stdout: stdout.to_string(),
                stderr: String::new(),
            }
        }
    }

    impl OrbExec for Script {
        async fn execute(&mut self, args: &[String]) -> Result<CommandResult> {
            self.calls.push(args.to_vec());
            if self.replies.is_empty() {
                panic!("no scripted reply for {args:?}");
            }
            Ok(self.replies.remove(0))
        }
    }

    fn create() -> Vec<String> {
        create_args(Distro::Debian, GuestArch::Amd64, true, 2, 2048, None, NAME).unwrap()
    }

    #[test]
    fn sweep_deletes_only_an_exact_name_whose_run_directory_is_gone() {
        let names = [
            "qlean-00a11e000001",
            "qlean-00a11e000002",
            "qlean-00a11e00000",
            "qlean-00a11e0000011",
            "clean-00a11e000003",
            "ubuntu",
        ];
        let doomed = sweep_names(names, |id| id == "00a11e000002");
        assert_eq!(doomed, vec!["qlean-00a11e000001".to_string()]);
    }

    #[tokio::test]
    async fn init_creates_once_and_shutdown_stops_without_deleting() {
        let mut script = Script {
            replies: vec![Script::ok("[]"), Script::ok(""), Script::ok("")],
            calls: Vec::new(),
        };
        let created = drive_init(&mut script, NAME, &create()).await.unwrap();
        assert!(created);
        drive_shutdown(&mut script, NAME).await.unwrap();
        assert_eq!(script.calls[0], list_args());
        assert_eq!(script.calls[1][0], "create");
        assert!(
            script
                .calls
                .iter()
                .filter(|call| call[0] == "create")
                .count()
                == 1
        );
        assert_eq!(
            script.calls.last().unwrap(),
            &vec!["stop".to_string(), NAME.to_string()]
        );
        assert!(script.calls.iter().all(|call| call[0] != "delete"));
    }

    #[tokio::test]
    async fn an_existing_name_is_started_instead_of_created_again() {
        let listed = format!(r#"[{{"name":"{NAME}","state":"stopped"}}]"#);
        let mut script = Script {
            replies: vec![Script::ok(&listed), Script::ok("")],
            calls: Vec::new(),
        };
        let created = drive_init(&mut script, NAME, &create()).await.unwrap();
        assert!(!created);
        assert!(script.calls.iter().all(|call| call[0] != "create"));
        assert_eq!(
            script.calls.last().unwrap(),
            &vec!["start".to_string(), NAME.to_string()]
        );
    }

    #[tokio::test]
    async fn a_failed_create_deletes_a_name_that_appeared_and_reports_cleanup_failure() {
        let mut script = Script {
            replies: vec![
                Script::ok("[]"),
                CommandResult {
                    success: false,
                    stdout: String::new(),
                    stderr: "boom".to_string(),
                },
                Script::ok(&format!(r#"[{{"name":"{NAME}","state":"running"}}]"#)),
                CommandResult {
                    success: false,
                    stdout: String::new(),
                    stderr: "delete failed".to_string(),
                },
            ],
            calls: Vec::new(),
        };
        let error = drive_init(&mut script, NAME, &create()).await.unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("boom"), "{message}");
        assert!(message.contains("delete failed"), "{message}");
        assert!(
            script
                .calls
                .iter()
                .any(|call| call.first().map(String::as_str) == Some("delete"))
        );
    }

    #[tokio::test]
    async fn a_failed_start_of_an_existing_machine_does_not_delete_it() {
        let listed = format!(r#"[{{"name":"{NAME}","state":"stopped"}}]"#);
        let mut script = Script {
            replies: vec![
                Script::ok(&listed),
                CommandResult {
                    success: false,
                    stdout: String::new(),
                    stderr: "start failed".to_string(),
                },
            ],
            calls: Vec::new(),
        };
        let error = drive_init(&mut script, NAME, &create()).await.unwrap_err();
        assert!(format!("{error:#}").contains("start failed"));
        script.replies.push(Script::ok(""));
        drive_failure(&mut script, NAME, false).await.unwrap();
        assert!(
            script
                .calls
                .iter()
                .any(|call| call.first().map(String::as_str) == Some("stop"))
        );
        assert!(
            script
                .calls
                .iter()
                .all(|call| call.first().map(String::as_str) != Some("delete"))
        );
    }

    #[test]
    fn power_distinguishes_running_stopped_and_a_broken_probe() {
        let running = r#"{"record":{"state":"running"},"ip4":"192.168.139.148"}"#;
        assert_eq!(parse_power(NAME, running, true).unwrap(), OrbPower::Running);
        let stopped = r#"{"record":{"state":"stopped"}}"#;
        assert_eq!(parse_power(NAME, stopped, true).unwrap(), OrbPower::Stopped);
        assert_eq!(
            parse_power(
                NAME,
                "[-32098] machine not found: 'qlean-00a11e000001'",
                false
            )
            .unwrap(),
            OrbPower::Absent
        );
        let error = parse_power(NAME, "not json", true).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains(NAME), "{message}");
        assert!(message.contains("not json"), "{message}");
    }
}

#[cfg(test)]
mod orb_guest_ip {
    use super::parse_ip4;

    const NAME: &str = "qlean-00a11e000001";

    #[test]
    fn the_address_comes_from_orb_info_ip4() {
        let stdout =
            r#"{"record":{"state":"running","name":"qlean-00a11e000001"},"ip4":"192.168.139.148"}"#;
        assert_eq!(parse_ip4(NAME, stdout, true).unwrap(), "192.168.139.148");
        let source = include_str!("orbstack.rs");
        let start = source.find("pub(crate) fn parse_ip4").expect("parse_ip4");
        let body = &source[start..start + 700];
        assert!(!body.contains("hostname -I"), "{body}");
    }

    #[test]
    fn a_missing_address_names_the_machine_and_the_output() {
        let error = parse_ip4(NAME, r#"{"record":{"state":"stopped"}}"#, true).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains(NAME), "{message}");
        assert!(message.contains("stopped"), "{message}");
        assert!(!message.contains("hostname -I"), "{message}");
    }

    #[test]
    fn a_failed_probe_keeps_a_one_line_summary() {
        let error = parse_ip4(NAME, "not json\nsecond", false).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains(NAME), "{message}");
        assert!(message.contains("not json second"), "{message}");
        assert!(!message.contains('\n'), "{message}");
    }
}

#[cfg(test)]
mod orb_ssh {
    use super::{display_orb_path, pinned_host_key, read_private_key, ssh_endpoint};
    use crate::ssh::host_key_rejection_message;

    #[test]
    fn the_endpoint_is_orbstack_localhost_ssh() {
        let endpoint =
            ssh_endpoint("qlean-00a11e000001", std::path::Path::new("/Users/someone")).unwrap();
        assert_eq!(endpoint.host, "127.0.0.1");
        assert_eq!(endpoint.port, 32222);
        assert_eq!(endpoint.user, "root@qlean-00a11e000001");
        assert_eq!(
            endpoint.key_path,
            std::path::PathBuf::from("/Users/someone/.orbstack/ssh/id_ed25519")
        );
        assert_eq!(
            display_orb_path(&endpoint.key_path),
            "~/.orbstack/ssh/id_ed25519"
        );
    }

    #[test]
    fn a_missing_private_key_names_the_path_and_authorized_keys() {
        let error = read_private_key(std::path::Path::new(
            "/Users/someone/.orbstack/ssh/id_ed25519",
        ))
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("~/.orbstack/ssh/id_ed25519"), "{message}");
        assert!(message.contains("authorized_keys"), "{message}");
        assert!(!message.contains("someone"), "{message}");
    }

    #[test]
    fn a_mismatched_host_key_names_orbstack() {
        let message = host_key_rejection_message("orbstack", true);
        assert!(message.contains("OrbStack's SSH service"), "{message}");
        assert!(message.contains("authorized_keys"), "{message}");
        assert!(message.contains("127.0.0.1:32222"), "{message}");
    }

    #[test]
    fn known_hosts_without_the_ed25519_line_fails() {
        let error = pinned_host_key("[127.0.0.1]:32222 ecdsa-sha2-nistp256 AAAA").unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("ssh-ed25519"), "{message}");
        assert!(message.contains("authorized_keys"), "{message}");
    }
}

#[cfg(all(test, target_os = "macos"))]
mod orb_lifecycle_live {
    use std::time::Duration;

    use crate::orbstack::{LiveOrb, OrbExec, list_args, machine_name, parse_list};
    use crate::{Distro, Image, ImageConfig, Machine, MachineConfig};

    /// Real OrbStack lifecycle. Not part of `cargo test --lib`.
    ///
    /// ```text
    /// cargo test --lib orb_lifecycle_live -- --ignored
    /// ```
    #[tokio::test]
    #[cfg_attr(
        target_os = "macos",
        ignore = "needs OrbStack: cargo test --lib orb_lifecycle_live -- --ignored"
    )]
    async fn orb_lifecycle_live() {
        let image = Image::new(ImageConfig::default().with_distro(Distro::Debian))
            .await
            .expect("debian does not download a qcow2 on macOS");
        let config = MachineConfig::default()
            .with_core(1)
            .with_mem(1024)
            .with_timeout(180);
        let mut machine = Machine::new(&image, &config).await.expect("construct");
        let name = machine_name(machine.id()).unwrap();
        machine.init().await.expect("init");
        let id = machine.exec("id -u").await.expect("exec");
        assert!(
            id.status.success(),
            "{}",
            String::from_utf8_lossy(&id.stderr)
        );
        assert_eq!(String::from_utf8_lossy(&id.stdout).trim(), "0");

        let dir = tempfile::tempdir().unwrap();
        let local = dir.path().join("hello.txt");
        std::fs::write(&local, b"orb-live").unwrap();
        machine
            .upload(&local, "/root/qlean-orb-live.txt")
            .await
            .expect("upload");
        let back = dir.path().join("back.txt");
        machine
            .download("/root/qlean-orb-live.txt", &back)
            .await
            .expect("download");
        assert_eq!(std::fs::read(&back).unwrap(), b"orb-live");

        machine.shutdown().await.expect("shutdown");
        let mut exec = LiveOrb;
        let listed = exec.execute(&list_args()).await.unwrap();
        let machines = parse_list(&listed.stdout).unwrap();
        assert!(
            machines.iter().any(|item| item.name == name),
            "shutdown must not delete {name}"
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
        machine.spawn().await.expect("spawn");
        let again = machine
            .exec("cat /root/qlean-orb-live.txt")
            .await
            .expect("exec after spawn");
        assert_eq!(String::from_utf8_lossy(&again.stdout).trim(), "orb-live");
        machine.shutdown().await.expect("shutdown again");
        let _ = exec
            .execute(&crate::orbstack::delete_args(&name).unwrap())
            .await;
    }
}
