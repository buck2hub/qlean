use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};

use dir_lock::DirLock;
use directories::ProjectDirs;
use rand::RngExt;
use tracing::{debug, trace, warn};
use walkdir::WalkDir;

pub(crate) static HEX_ALPHABET: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];

pub(crate) const VIRSH_CONNECTION_URI: &str = "qemu:///system";
pub(crate) const QLEAN_BRIDGE_NAME: &str = "qlbr0";

// NOTE: `derive_mac()` was previously used by an experimental multi-NIC TCP hostfwd
// path. The current implementation is vsock-only, so we avoid keeping unused code
// that triggers `dead_code` warnings.

/// A DHCP lease observed on Qlean's libvirt network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DhcpLease {
    /// Lowercase MAC address as reported by libvirt.
    pub mac: String,
    /// Address handed to that MAC.
    pub ip: std::net::IpAddr,
    /// Expiry exactly as libvirt printed it (`YYYY-MM-DD HH:MM:SS`), `infinite` for a
    /// lease that never expires, and empty if the row carried no recognizable expiry.
    ///
    /// The table can hold several rows for one MAC (an expiring lease next to the one
    /// renewed after it), so rows are compared by this field to pick the current address.
    /// The three spellings are ordered on purpose: a real timestamp sorts below the word
    /// `infinite`, and an unrecognized expiry sorts below both, so the most durable claim
    /// on the MAC wins and an unreadable row can never outrank a readable one.
    pub expiry: String,
}

/// How long one `virsh` call may take.
///
/// These are local RPCs against `libvirtd`; on a healthy host each finishes in milliseconds.
/// The budget exists for the unhealthy case: a wedged `libvirtd` (or a socket that never
/// answers) must fail the launch with a message instead of hanging it.
const VIRSH_CALL_BUDGET: std::time::Duration = std::time::Duration::from_secs(60);

/// How long a prerequisite probe (`<program> --version`) may take.
const PROBE_BUDGET: std::time::Duration = std::time::Duration::from_secs(10);

/// Why a bounded run produced no output.
///
/// Kept as a type rather than a string so callers can tell the two failures apart: "could not
/// start it" is a missing dependency, while "killed it at the deadline" is a blocked one, and
/// the two need opposite advice.
pub(crate) enum BoundedFailure {
    /// The program never started.
    NotRun(anyhow::Error),
    /// The program was still running at the deadline and was killed.
    Killed {
        /// Name of the program that was killed.
        program: String,
        /// The budget it exceeded.
        budget: std::time::Duration,
        /// What the caller was trying to do.
        what: String,
    },
}

impl std::fmt::Display for BoundedFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotRun(error) => write!(formatter, "{error}"),
            Self::Killed {
                program,
                budget,
                what,
            } => write!(
                formatter,
                "`{program}` did not finish within {budget:?} while trying to {what}; \
                 the process was killed"
            ),
        }
    }
}

impl std::fmt::Debug for BoundedFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, formatter)
    }
}

/// Run `cmd` and collect its output, but never wait longer than `budget`.
///
/// A budget that does not also end the child process is not a budget: `kill_on_drop`
/// kills it when the output future is dropped at the deadline, so nothing keeps running
/// (and writing the file it was told to write) after the caller gave up.
pub(crate) async fn run_bounded(
    mut cmd: tokio::process::Command,
    budget: std::time::Duration,
    what: &str,
) -> std::result::Result<std::process::Output, BoundedFailure> {
    let program = cmd.as_std().get_program().to_string_lossy().into_owned();
    cmd.kill_on_drop(true);
    match tokio::time::timeout(budget, cmd.output()).await {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(error)) => Err(BoundedFailure::NotRun(error.into())),
        Err(_) => Err(BoundedFailure::Killed {
            program,
            budget,
            what: what.to_string(),
        }),
    }
}

/// `run_bounded`, flattened into `anyhow` for the callers that only report the failure.
pub(crate) async fn bounded_output(
    cmd: tokio::process::Command,
    budget: std::time::Duration,
    what: &str,
) -> Result<std::process::Output> {
    run_bounded(cmd, budget, what)
        .await
        .map_err(|failure| anyhow::anyhow!("{failure}"))
}

/// Normalize a MAC address for comparison (`-`, `:` and case are not significant).
///
/// One implementation, used by both the DHCP lease path and the in-guest address query:
/// two normalizers would eventually disagree about what "the same MAC" means.
pub(crate) fn normalize_mac(mac: &str) -> String {
    mac.chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_ascii_lowercase()
}

/// Parse `virsh net-dhcp-leases` tabular output.
///
/// Example row:
/// ` 2026-11-12 09:35:00   52:54:00:aa:bb:cc   ipv4       192.168.221.42/24    *  -`
pub(crate) fn parse_dhcp_leases(output: &str) -> Vec<DhcpLease> {
    /// A MAC token is six hex pairs, separated by `:` or by `-`.
    ///
    /// Both spellings are accepted because the same address is printed differently by
    /// the tools involved (`virsh` uses `:`, Windows reports `-`). Rejecting one spelling
    /// would silently skip the row and surface as "no lease ever appeared", which points
    /// at DHCP instead of at the parser.
    fn looks_like_mac(token: &str) -> bool {
        let separator = if token.contains(':') {
            ':'
        } else if token.contains('-') {
            '-'
        } else {
            return false;
        };
        let parts = token.split(separator).collect::<Vec<_>>();
        parts.len() == 6
            && parts
                .iter()
                .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
    }

    let mut leases = Vec::new();
    for line in output.lines() {
        let tokens = line.split_whitespace().collect::<Vec<_>>();
        let Some(mac_index) = tokens.iter().position(|t| looks_like_mac(t)) else {
            continue;
        };
        // The address column follows the protocol column and carries a prefix.
        let Some(ip) = tokens[mac_index + 1..].iter().find_map(|t| {
            let (addr, _prefix) = t.split_once('/')?;
            addr.parse::<std::net::IpAddr>().ok()
        }) else {
            continue;
        };
        leases.push(DhcpLease {
            mac: tokens[mac_index].to_ascii_lowercase(),
            ip,
            expiry: parse_lease_expiry(line),
        });
    }
    leases
}

/// `YYYY-MM-DD HH:MM:SS` prefix of a lease row, or an empty string.
///
/// Kept as a string on purpose: that format sorts chronologically, so the newest lease
/// can be selected without pulling in a date/time crate.
fn parse_lease_expiry(line: &str) -> String {
    fn looks_like_date(token: &str) -> bool {
        let parts = token.split('-').collect::<Vec<_>>();
        parts.len() == 3
            && parts[0].len() == 4
            && parts[1].len() == 2
            && parts[2].len() == 2
            && parts.iter().all(|p| p.chars().all(|c| c.is_ascii_digit()))
    }

    let tokens = line.split_whitespace().collect::<Vec<_>>();
    let parsed = match tokens.as_slice() {
        [date, time, ..]
            if looks_like_date(date)
                && time.len() == 8
                && time.chars().enumerate().all(|(index, c)| {
                    if index % 3 == 2 {
                        c == ':'
                    } else {
                        c.is_ascii_digit()
                    }
                }) =>
        {
            Some(format!("{date} {time}"))
        }
        _ => None,
    };
    if let Some(expiry) = parsed {
        return expiry;
    }
    // `virsh` prints `infinite` for a lease that never expires (a static host entry or a
    // reservation). It has to outrank every real timestamp when rows are compared, because
    // the address that never expires is the one the guest keeps; ranking it lowest would
    // hand back an abandoned dynamic address instead.
    if tokens
        .iter()
        .any(|token| token.eq_ignore_ascii_case("infinite"))
    {
        return "infinite".to_string();
    }
    String::new()
}

/// Leased IPv4 address of `mac`, if the lease table has one.
///
/// A dual-stack network reports a separate IPv6 lease for the same MAC, and its
/// address is often link-local (`fe80::/10`), which is useless without a scope id.
/// Only IPv4 is returned; an IPv6-only guest keeps polling and then fails with the
/// lease list instead of connecting to an unusable address.
///
/// libvirt keeps a row per lease, so one MAC can appear twice after a renewal. The
/// newest row (latest expiry) is the address the guest is actually using; taking the
/// first row instead dials the address it has already abandoned.
fn lease_address_for(leases: &[DhcpLease], mac: &str) -> Option<std::net::IpAddr> {
    // Compare the addresses, not the strings: the caller's MAC and the lease column may
    // differ in separator and case without being different addresses.
    let expected = normalize_mac(mac);
    leases
        .iter()
        .filter(|lease| normalize_mac(&lease.mac) == expected && lease.ip.is_ipv4())
        .max_by(|a, b| a.expiry.cmp(&b.expiry))
        .map(|lease| lease.ip)
}

/// Resolve a MAC address to its leased address on Qlean's libvirt network.
///
/// Polling is bounded by `timeout` and never runs an unbounded retry loop: the deadline
/// ends the wait, and every `virsh` call is capped by the remaining budget too, so a wedged
/// libvirtd cannot outlive the deadline by hanging inside one call. The guest
/// must be given the chance to reach DHCP, so transient "no lease yet" results are
/// expected until the address appears.
pub(crate) async fn find_lease_address(
    mac: &str,
    timeout: std::time::Duration,
) -> Result<std::net::IpAddr> {
    find_lease_address_with(mac, timeout, VIRSH_PROGRAM).await
}

/// Program name used to read the lease table.
const VIRSH_PROGRAM: &str = "virsh";

/// [`find_lease_address`] with an explicit lease-table program.
///
/// Exists so a test can point the lookup at a program that is not installed without
/// rewriting the process environment, which other tests in the same binary share.
async fn find_lease_address_with(
    mac: &str,
    timeout: std::time::Duration,
    program: &str,
) -> Result<std::net::IpAddr> {
    let mac = mac.to_ascii_lowercase();
    let deadline = tokio::time::Instant::now() + timeout;
    let mut last_seen = Vec::new();
    // A failing `virsh` is not the same finding as "the guest has no lease": libvirt may be
    // down or unreadable, and blaming the guest for 900s sends the reader to the wrong
    // machine. Track both facts so the timeout can say which one happened.
    let mut saw_a_listing = false;
    let mut last_error: Option<String> = None;

    loop {
        let mut cmd = tokio::process::Command::new(program);
        cmd.arg("-c")
            .arg(VIRSH_CONNECTION_URI)
            .arg("net-dhcp-leases")
            .arg("qlean");

        // One wedged `virsh` must not outlive the deadline: cap the call by whatever is
        // left of the budget (at least a millisecond, so the loop always makes progress).
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let budget = remaining.max(std::time::Duration::from_millis(1));
        match run_bounded(cmd, budget, "read the DHCP lease table").await {
            Ok(output) if output.status.success() => {
                saw_a_listing = true;
                last_seen = parse_dhcp_leases(&String::from_utf8_lossy(&output.stdout));
                if let Some(ip) = lease_address_for(&last_seen, &mac) {
                    debug!("MAC {mac} leased {ip}");
                    return Ok(ip);
                }
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                debug!("virsh net-dhcp-leases failed: {stderr}");
                last_error = Some(stderr);
            }
            Err(BoundedFailure::NotRun(error)) => {
                // Waiting cannot install a program. On a Windows first boot this lookup runs
                // under the whole deployment budget, so polling a missing `virsh` would spend
                // 900s to discover a fact that was knowable before the guest started — and
                // then blame libvirt access or the guest's DHCP.
                bail!(
                    "no DHCP lease table can be read: `{program}` is not available ({error:#}).\n\
                     Windows guests discover their address through `{program} net-dhcp-leases`, \
                     so install the `libvirt` package (and its `{program}` client) before \
                     starting a Windows guest"
                );
            }
            Err(error) => {
                // The call itself was abandoned; that is a libvirt finding, not a guest one.
                let error = format!("{error:#}");
                debug!("{error}");
                last_error = Some(error);
            }
        }

        if tokio::time::Instant::now() >= deadline {
            bail!(
                "{}",
                lease_timeout_message(
                    timeout,
                    &mac,
                    &last_seen,
                    saw_a_listing,
                    last_error.as_deref()
                )
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

/// Explain a lease lookup that ran out of budget.
///
/// The two causes need different words: when `virsh` never answered, the guest was never
/// asked and nothing is known about it; when it did answer, the listed leases are the
/// evidence. Reporting the first case as "the guest may still be booting" would point at
/// the guest while the real problem is the host's libvirt.
fn lease_timeout_message(
    timeout: std::time::Duration,
    mac: &str,
    last_seen: &[DhcpLease],
    saw_a_listing: bool,
    last_error: Option<&str>,
) -> String {
    let listed = last_seen
        .iter()
        .map(|lease| format!("{}={} (expires {})", lease.mac, lease.ip, lease.expiry))
        .collect::<Vec<_>>();
    if !saw_a_listing {
        return format!(
            "could not read DHCP leases on the `qlean` network within {}s: `virsh \
             net-dhcp-leases` never succeeded, so the guest was never checked (last error: {}).\n\
             Fix libvirt access first: `virsh -c {VIRSH_CONNECTION_URI} net-list --all` must work \
             as this user.",
            timeout.as_secs(),
            last_error.unwrap_or("none reported")
        );
    }
    let last_error = last_error
        .map(|error| format!("\nThe last `virsh net-dhcp-leases` call failed: {error}"))
        .unwrap_or_default();
    format!(
        "no DHCP lease for MAC {mac} on the `qlean` network within {}s (leases seen: {listed:?}).\n\
         The guest may still be booting, or it did not bring up its virtio network device.\n\
         Only IPv4 leases are usable: an IPv6-only lease is reported above but never dialled.{last_error}",
        timeout.as_secs()
    )
}

pub(crate) struct QleanDirs {
    pub base: PathBuf,
    pub images: PathBuf,
    pub secrets: PathBuf,
    pub runs: PathBuf,
}

impl QleanDirs {
    pub(crate) fn new() -> Result<Self> {
        let project_dir = project_dir_or_explain(ProjectDirs::from("", "", "qlean"))?;

        // Dir containing persistent data (usually ~/.local/share/qlean/)
        let data_dir = project_dir.data_dir().to_path_buf();
        create_dir("data", &data_dir)?;

        // Dir containing cached images (usually ~/.local/share/qlean/images/)
        let images = data_dir.join("images");
        create_dir("images", &images)?;

        // Dir containing secrets (usually ~/.local/share/qlean/secrets/)
        let secrets = data_dir.join("secrets");
        create_dir("secrets", &secrets)?;

        // Dir containing all runs (usually ~/.local/share/qlean/runs/)
        let runs = data_dir.join("runs");
        create_dir("runs", &runs)?;
        Ok(Self {
            base: data_dir,
            images,
            secrets,
            runs,
        })
    }
}

/// Explain why Qlean has no data directory instead of panicking inside `ProjectDirs`.
///
/// `ProjectDirs::from` returns `None` when neither `XDG_DATA_HOME` nor `HOME` is usable
/// (containers, `env -i`, system services, `sudo` without a preserved environment). Every
/// public entry point calls [`QleanDirs::new`], and `Drop for Machine` calls it as well, so
/// a panic here aborts the process instead of reporting the actual problem.
fn project_dir_or_explain(dirs: Option<ProjectDirs>) -> Result<ProjectDirs> {
    dirs.ok_or_else(|| {
        anyhow::anyhow!(
            "cannot determine Qlean's data directory: neither `XDG_DATA_HOME` nor `HOME` is \
             set to a usable absolute path. Set one of them (for example \
             `XDG_DATA_HOME=/var/lib/qlean`) and retry"
        )
    })
}

pub(crate) fn create_dir(purpose: &str, path: &Path) -> Result<()> {
    if !path.exists() {
        debug!("{purpose} dir {path:?} doesn't exist yet, creating");
        std::fs::create_dir_all(path)
            .with_context(|| format!("failed to create the {purpose} directory {path:?}"))?;
    }
    // Qlean's directories hold the client private key, per-VM host keys and seed media,
    // so they must not be traversable by other local users even when the umask allows it.
    restrict_dir(path)
}

/// Build a `key=path` command-line argument without lossy path conversion.
///
/// `format!("{key}={}", path.display())` (and `to_string_lossy`) replaces non-UTF-8 bytes
/// with `U+FFFD`, so a home directory that is not valid UTF-8 would silently point the
/// tool at a different, non-existent path. `OsString` keeps the bytes intact.
pub(crate) fn path_argument(prefix: &str, path: &Path) -> std::ffi::OsString {
    let mut argument = std::ffi::OsString::from(prefix);
    argument.push(path.as_os_str());
    argument
}

/// Make a file owner-only and owner-writable (`0600`).
///
/// Files Qlean generates hold secrets (client keys, seeds) or firmware state, and a copy of
/// a file can inherit the source's mode: `std::fs::copy` reproduces the permission bits, so
/// a stock `0444` OVMF vars template would become a per-VM pflash image the owner cannot
/// write, which QEMU reports as a read-only firmware device.
pub(crate) fn restrict_file(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(
            |error| anyhow::anyhow!("failed to restrict {} to 0600: {error}", path.display()),
        )?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Make a directory owner-only (`0700`).
///
/// Applied to every directory Qlean creates and to the per-VM run directory, so the
/// private keys and seed media inside are protected by their enclosing directory as well
/// as by their own mode.
pub(crate) fn restrict_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(
            |error| anyhow::anyhow!("failed to restrict {} to 0700: {error}", path.display()),
        )?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

pub(crate) fn get_free_cid(runs_dir: &Path, run_dir: &Path) -> Result<u32> {
    let mut cids = vec![];

    let runs_dir = runs_dir.to_owned();
    let run_dir = run_dir.to_owned();

    let lock_dir = runs_dir.join("lockdir");
    trace!("Trying to lock {lock_dir:?}");
    let lock = DirLock::new_sync(&lock_dir)?;

    for entry in WalkDir::new(runs_dir) {
        let entry = entry?;
        let filename = entry.file_name();
        if filename.to_string_lossy() == "cid" {
            trace!("Found CID file at {:?}", entry.path());
            let cid = std::fs::read_to_string(entry.path())?;
            cids.push(cid.parse::<u32>()?);
        }
    }

    // Get the next CID.
    cids.sort();
    let cid = if let Some(last_cid) = cids.iter().next_back() {
        last_cid + 1
    } else {
        // We get here if the current list of CIDs is empty. So we'll just start with some
        // arbitrary CID.
        10
    };

    debug!("Our new CID: {cid}");
    std::fs::write(run_dir.join("cid"), cid.to_string())?;

    trace!("Unlocking {lock_dir:?}");
    drop(lock);

    Ok(cid)
}

pub trait CommandExt {
    fn to_string(&self) -> String;
}

impl CommandExt for tokio::process::Command {
    fn to_string(&self) -> String {
        let program_str = self.as_std().get_program().to_string_lossy();
        let args_str = self
            .as_std()
            .get_args()
            .map(|x| x.to_string_lossy())
            .map(|x| {
                // Make sure that commands that contain spaces will be properly quoted.
                if x.contains(' ') {
                    format!("\"{x}\"")
                } else {
                    format!("{x}")
                }
            })
            .collect::<Vec<_>>()
            .join(" ");
        format!("{program_str} {args_str}")
    }
}

/// Programs Qlean shells out to, whatever the guest OS is.
const REQUIRED_PROGRAMS: [&str; 4] = ["qemu-system-x86_64", "qemu-img", "xorriso", "virsh"];

/// Helper QEMU execs to attach a VM to the host bridge.
///
/// `-netdev bridge,br=...` does not open the tap itself: QEMU runs this helper, which every
/// distro installs outside `PATH` (in `libexec`), so it needs its own probe instead of the
/// `PATH` lookup the CLI programs above get.
const BRIDGE_HELPER_PROGRAM: &str = "qemu-bridge-helper";

/// Where a distro may put [`BRIDGE_HELPER_PROGRAM`], most specific first.
const BRIDGE_HELPER_CANDIDATES: [&str; 3] = [
    "/usr/lib/qemu/qemu-bridge-helper",
    "/usr/libexec/qemu-bridge-helper",
    "/usr/local/libexec/qemu-bridge-helper",
];

/// Locate the bridge helper, preferring a known install path over one on `PATH`.
fn bridge_helper_path(exists: impl Fn(&Path) -> bool, on_path: bool) -> Option<PathBuf> {
    BRIDGE_HELPER_CANDIDATES
        .iter()
        .map(Path::new)
        .find(|candidate| exists(candidate))
        .map(Path::to_path_buf)
        .or_else(|| on_path.then(|| PathBuf::from(BRIDGE_HELPER_PROGRAM)))
}

/// Explain a missing bridge helper, including the second thing that breaks bridging.
fn bridge_helper_problem(found: Option<&Path>) -> Option<String> {
    found.is_none().then(|| {
        format!(
            "`{BRIDGE_HELPER_PROGRAM}` was not found in {} or on `PATH`: QEMU runs it to attach a VM to \
             the `qlbr0` bridge. Install the QEMU package that ships it, and make sure \
             `/etc/qemu/bridge.conf` contains `allow qlbr0`",
            BRIDGE_HELPER_CANDIDATES.join(", ")
        )
    })
}

/// Whether `program` is found by a bare-name lookup, as `Command::new` would run it.
fn program_on_path(program: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| dir.join(program).is_file())
}

/// Ensure the guest-independent host prerequisites (CLI tools, bridge helper, network).
pub(crate) async fn ensure_host_prerequisites() -> Result<()> {
    let mut problems = check_commands_available(&REQUIRED_PROGRAMS).await;
    let helper = bridge_helper_path(
        |path| path.is_file(),
        program_on_path(BRIDGE_HELPER_PROGRAM),
    );
    problems.extend(bridge_helper_problem(helper.as_deref()));

    anyhow::ensure!(
        problems.is_empty(),
        "required host programs are missing:\n- {}",
        problems.join("\n- ")
    );

    ensure_network().await?;
    Ok(())
}

/// Ensure host prerequisites for running virtual machines of `guest_os`.
///
/// vsock is only required by Linux guests: Windows guests are reached over the
/// libvirt NAT network, so a host without `/dev/vhost-vsock` can still run them.
pub(crate) async fn ensure_prerequisites(guest_os: crate::image::GuestOs) -> Result<()> {
    ensure_host_prerequisites().await?;
    if guest_os == crate::image::GuestOs::Linux {
        ensure_vsock()?;
    }
    Ok(())
}

/// How probing one required program turned out.
#[derive(Debug)]
enum ProgramProbe {
    /// The program answered `--version`.
    Available,
    /// The program is not on `PATH` (or cannot be executed).
    Missing(String),
    /// The program exists but `--version` failed, so the installation is broken.
    Broken(String),
    /// The program exists but did not answer `--version` inside the probe budget.
    Unusable(String),
}

/// Turn probe results into the lines of a single aggregated error.
///
/// Installing one package per failed run is what this avoids: the caller reports every
/// missing or broken program at once.
fn program_problems(probes: &[(&str, ProgramProbe)]) -> Vec<String> {
    probes
        .iter()
        .filter_map(|(program, probe)| match probe {
            ProgramProbe::Available => None,
            ProgramProbe::Missing(reason) => Some(format!(
                "`{program}` is required but was not found ({reason}): install it and try again"
            )),
            ProgramProbe::Broken(status) => Some(format!(
                "`{program}` is installed but `{program} --version` failed ({status}): the installation looks broken"
            )),
            // A program that hangs is installed: telling the user to install it sends them
            // to the wrong problem, and the missing/broken cases above already cover the
            // reasons it would genuinely be absent.
            ProgramProbe::Unusable(reason) => Some(format!(
                "`{program}` did not answer `{program} --version` ({reason}): it is installed but blocked, so \
                 check what it is waiting on (a stale lock, an unreachable mount) instead of reinstalling it"
            )),
        })
        .collect()
}

/// Probe every program, returning the aggregated problem lines (empty when all are usable).
async fn check_commands_available(programs: &[&'static str]) -> Vec<String> {
    let mut probes = Vec::with_capacity(programs.len());
    for program in programs {
        let mut probe_command = tokio::process::Command::new(program);
        probe_command.arg("--version");
        let probe = match run_bounded(probe_command, PROBE_BUDGET, "probe the program").await {
            Ok(output) if output.status.success() => ProgramProbe::Available,
            // A program that cannot run `--version` is not usable, even if it exists.
            Ok(output) => ProgramProbe::Broken(output.status.to_string()),
            Err(failure @ BoundedFailure::Killed { .. }) => {
                ProgramProbe::Unusable(failure.to_string())
            }
            Err(BoundedFailure::NotRun(error)) => ProgramProbe::Missing(error.to_string()),
        };
        probes.push((*program, probe));
    }

    program_problems(&probes)
}

fn ensure_vsock() -> Result<()> {
    if !Path::new("/dev/vhost-vsock").exists() {
        bail!(
            "`/dev/vhost-vsock` is missing. Qlean requires vhost-vsock for SSH. Please ensure it is available and try again."
        );
    }
    Ok(())
}

async fn ensure_network() -> Result<()> {
    let mut command = tokio::process::Command::new("virsh");
    command
        .arg("-c")
        .arg(VIRSH_CONNECTION_URI)
        .arg("net-list")
        .arg("--name")
        .arg("--all");
    let output = bounded_output(command, VIRSH_CALL_BUDGET, "list every libvirt network")
        .await
        .context("failed to execute virsh to check qlean network")?;
    let all_networks = listed_networks(&output, "net-list --all")?;
    let net_exists = all_networks.contains("qlean");

    let mut command = tokio::process::Command::new("virsh");
    command
        .arg("-c")
        .arg(VIRSH_CONNECTION_URI)
        .arg("net-list")
        .arg("--name");
    let output = bounded_output(
        command,
        VIRSH_CALL_BUDGET,
        "list the active libvirt networks",
    )
    .await
    .context("failed to execute virsh to check qlean network")?;
    let active_networks = listed_networks(&output, "net-list")?;
    let net_active = active_networks.contains("qlean");

    // QEMU is always launched with `br={QLEAN_BRIDGE_NAME}`, so a `qlean` network that
    // exists but hands out a different bridge cannot work: QEMU would fail to attach the
    // NIC and the guest would never get a lease. Fail here, where the mismatch is
    // visible, instead of deep inside a QEMU error message.
    if net_exists {
        let bridge = existing_network_bridge().await?;
        match bridge.as_deref() {
            Some(name) if name != QLEAN_BRIDGE_NAME => {
                bail!("{}", bridge_mismatch_message(name));
            }
            Some(_) => {}
            None => warn!("{}", bridge_assumed_message()),
        }
    }

    if !net_exists {
        debug!("Creating qlean network");
        let xml = r#"
<network>
  <name>qlean</name>
  <bridge name='qlbr0'/>
  <forward mode="nat"/>
  <ip address='192.168.221.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='192.168.221.2' end='192.168.221.254'/>
    </dhcp>
  </ip>
</network>
"#;
        let dirs = QleanDirs::new()?;
        let xml_path = dirs.base.join("network.xml");
        tokio::fs::write(&xml_path, xml)
            .await
            .context("failed to write qlean network xml file")?;

        let mut command = tokio::process::Command::new("virsh");
        command
            .arg("-c")
            .arg(VIRSH_CONNECTION_URI)
            .arg("net-define")
            .arg(&xml_path);
        let output = bounded_output(command, VIRSH_CALL_BUDGET, "define the qlean network")
            .await
            .context("failed to execute virsh to define qlean network")?;
        if !output.status.success() {
            bail!(
                "failed to define the qlean network: {}",
                virsh_reason(&output)
            );
        }
    }

    if !net_exists || !net_active {
        debug!("Starting qlean network");
        let mut command = tokio::process::Command::new("virsh");
        command
            .arg("-c")
            .arg(VIRSH_CONNECTION_URI)
            .arg("net-autostart")
            .arg("qlean");
        let output = bounded_output(
            command,
            VIRSH_CALL_BUDGET,
            "mark the qlean network autostart",
        )
        .await
        .context("failed to execute virsh to autostart qlean network")?;
        if !output.status.success() {
            bail!(
                "failed to autostart the qlean network: {}",
                virsh_reason(&output)
            );
        }

        let mut command = tokio::process::Command::new("virsh");
        command
            .arg("-c")
            .arg(VIRSH_CONNECTION_URI)
            .arg("net-start")
            .arg("qlean");
        let output = bounded_output(command, VIRSH_CALL_BUDGET, "start the qlean network")
            .await
            .context("failed to execute virsh to start qlean network")?;
        if !output.status.success() {
            bail!(
                "failed to start the qlean network: {}",
                virsh_reason(&output)
            );
        }
    }
    Ok(())
}

/// The reason a virsh invocation failed: its stderr, so libvirt's own message reaches the user.
fn virsh_reason(output: &std::process::Output) -> String {
    let reason = String::from_utf8_lossy(&output.stderr);
    let reason = reason.trim();
    if reason.is_empty() {
        format!("`virsh` exited with {}", output.status)
    } else {
        format!("`virsh` exited with {}: {reason}", output.status)
    }
}

/// Networks reported by a `virsh net-list --name` invocation.
///
/// A failed listing is an error, never an empty list. Reading it as "no such network" sends
/// the user down the create-the-network path when the actual problem is that libvirt is
/// unreachable, and the useful message (libvirt's own) is what they need to see.
fn listed_networks(output: &std::process::Output, what: &str) -> Result<HashSet<String>> {
    if !output.status.success() {
        bail!(
            "`virsh -c {VIRSH_CONNECTION_URI} {what}` failed, so the qlean network state is \
             unknown (is libvirtd running and reachable?): {}",
            virsh_reason(output)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_owned)
        .filter(|line| !line.trim().is_empty())
        .collect())
}

/// Message for a `qlean` network whose bridge name could not be read.
fn bridge_assumed_message() -> String {
    format!(
        "could not read the bridge name of the existing `qlean` network; assuming it is \
         {QLEAN_BRIDGE_NAME}. If guest networking fails, recreate the network with \
         `virsh -c {VIRSH_CONNECTION_URI} net-undefine qlean` and run the command again"
    )
}

/// Bridge name of the existing `qlean` libvirt network.
async fn existing_network_bridge() -> Result<Option<String>> {
    let mut command = tokio::process::Command::new("virsh");
    command
        .arg("-c")
        .arg(VIRSH_CONNECTION_URI)
        .arg("net-dumpxml")
        .arg("qlean");
    let output = bounded_output(
        command,
        VIRSH_CALL_BUDGET,
        "read the qlean network definition",
    )
    .await
    .context("failed to read the qlean network definition")?;
    if !output.status.success() {
        bail!(
            "`virsh net-dumpxml qlean` failed ({}); cannot verify that the network provides \
             the {QLEAN_BRIDGE_NAME} bridge",
            output.status
        );
    }
    Ok(network_bridge_name(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

/// Extract the bridge name from `virsh net-dumpxml` output.
///
/// Tolerant on purpose: the attribute may use single or double quotes, and other elements
/// (`<name>`, `<uuid>`) carry attributes that must not be mistaken for the bridge. Only the
/// `<bridge .../>` element is inspected, and a missing bridge element yields `None` rather
/// than a guess.
pub(crate) fn network_bridge_name(xml: &str) -> Option<String> {
    let start = xml.find("<bridge")?;
    let rest = &xml[start + "<bridge".len()..];
    let end = rest.find("/>").or_else(|| rest.find('>'))?;
    let element = &rest[..end];
    let name_at = element.find("name")?;
    let after = &element[name_at + "name".len()..];
    let value = after.get(after.find('=')? + 1..)?.trim_start();
    let quote = value.chars().next()?;
    if quote != '\'' && quote != '"' {
        return None;
    }
    let rest = &value[1..];
    Some(rest[..rest.find(quote)?].to_string())
}

/// Actionable message for a `qlean` network that does not provide Qlean's bridge.
fn bridge_mismatch_message(found: &str) -> String {
    format!(
        "the existing libvirt network `qlean` uses bridge `{found}`, but Qlean attaches every \
         guest to `{QLEAN_BRIDGE_NAME}`; the guest would never receive a DHCP lease.\n\
         Recreate the network so Qlean owns it:\n  \
         virsh -c {VIRSH_CONNECTION_URI} net-destroy qlean\n  \
         virsh -c {VIRSH_CONNECTION_URI} net-undefine qlean\n\
         then run the command again."
    )
}

pub(crate) fn gen_random_mac() -> String {
    let mut rng = rand::rng();
    let bytes: [u8; 6] = [0x52, 0x54, 0x00, rng.random(), rng.random(), rng.random()];
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

/// `User-Agent` for HTTP requests Qlean makes on the user's behalf.
///
/// Derived from the crate version on purpose: this string is how a mirror operator
/// identifies the client, and a hand-written version silently keeps advertising the release
/// it was typed in (it already said `0.3.0` while the crate was `0.3.1`).
pub(crate) fn qlean_user_agent() -> &'static str {
    concat!("qlean/", env!("CARGO_PKG_VERSION"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEASES_HEADER: &str = "\
 Expiry Time           MAC address         Protocol   IP address           Hostname   Client ID or DUID
---------------------------------------------------------------------------------------------------------
";

    /// A lease table that no installed program can read must be reported at once.
    ///
    /// Windows guests learn their address only through `virsh net-dhcp-leases`, and on a
    /// first boot this lookup runs under the whole deployment budget. Polling a program that
    /// is not installed turns "install libvirt" into a spent 900s wait whose message points
    /// at libvirt access or at the guest's DHCP — the same finding, reported 15 minutes late
    /// and aimed at the wrong machine.
    #[tokio::test]
    async fn test_a_missing_lease_tool_fails_at_once_instead_of_polling() {
        let start = std::time::Instant::now();
        let error = find_lease_address_with(
            "52:54:00:aa:bb:cc",
            std::time::Duration::from_secs(30),
            "/nonexistent/virsh",
        )
        .await
        .expect_err("a program that does not exist cannot answer");
        let elapsed = start.elapsed();

        let message = format!("{error:#}");
        assert!(message.contains("/nonexistent/virsh"), "{message}");
        assert!(message.contains("libvirt"), "{message}");
        // The whole 30s budget must not be spent on a fact already known at the first poll.
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "waited {elapsed:?} for a program that is not installed"
        );
    }

    #[test]
    fn test_parse_dhcp_leases_maps_mac_to_address() {
        let output = format!(
            "{LEASES_HEADER} 2026-11-12 09:35:00   52:54:00:aa:bb:cc   ipv4       192.168.221.42/24    *          -\n\
             2026-11-12 09:36:00   52:54:00:11:22:33   ipv4       192.168.221.43/24    *          -\n"
        );
        let leases = parse_dhcp_leases(&output);
        assert_eq!(leases.len(), 2);
        assert_eq!(leases[0].mac, "52:54:00:aa:bb:cc");
        assert_eq!(leases[0].ip.to_string(), "192.168.221.42");
        assert_eq!(leases[1].mac, "52:54:00:11:22:33");
        assert_eq!(leases[1].ip.to_string(), "192.168.221.43");
    }

    #[test]
    fn test_looks_like_mac_accepts_both_separators_and_nothing_looser() {
        // Rows are matched by a scanner, so anything that merely looks MAC-ish must not be
        // picked up: a bare 12-hex-digit token or a mixed separator is not an address.
        let output = format!(
            "{LEASES_HEADER} 2026-11-12 09:35:00   52-54-00-AA-BB-CC   ipv4       192.168.221.42/24    *  -\n\
             2026-11-12 09:35:00   525400112233            ipv4       192.168.221.43/24    *  -\n\
             2026-11-12 09:35:00   52-54:00-aa:bb:cc       ipv4       192.168.221.44/24    *  -\n"
        );
        let leases = parse_dhcp_leases(&output);
        assert_eq!(leases.len(), 1, "only the dashed MAC is a MAC: {leases:?}");
        assert_eq!(leases[0].ip.to_string(), "192.168.221.42");
        // A dashed lease matches a colon-shaped query: same address, different spelling.
        assert_eq!(
            lease_address_for(&leases, "52:54:00:aa:bb:cc").map(|ip| ip.to_string()),
            Some("192.168.221.42".to_string())
        );
        assert_eq!(
            lease_address_for(&leases, "52-54-00-AA-BB-CC").map(|ip| ip.to_string()),
            Some("192.168.221.42".to_string())
        );
    }

    #[test]
    fn test_parse_dhcp_leases_normalizes_mac_case() {
        let output = format!(
            "{LEASES_HEADER} 2026-11-12 09:35:00   52:54:00:AA:BB:CC   ipv4       192.168.221.42/24    *  -\n"
        );
        let leases = parse_dhcp_leases(&output);
        assert_eq!(leases[0].mac, "52:54:00:aa:bb:cc");
    }

    #[test]
    fn test_parse_dhcp_leases_ignores_header_and_empty_output() {
        assert!(parse_dhcp_leases("").is_empty());
        assert!(parse_dhcp_leases(LEASES_HEADER).is_empty());
        // A row without a parseable address must not produce a bogus lease.
        let output =
            " 2026-11-12 09:35:00   52:54:00:aa:bb:cc   ipv4       <unavailable>    *  -\n";
        assert!(parse_dhcp_leases(output).is_empty());
    }

    #[test]
    fn test_lease_address_for_prefers_ipv4_on_a_dual_stack_network() {
        let output = format!(
            "{LEASES_HEADER} 2026-11-12 09:35:00   52:54:00:aa:bb:cc   ipv6       fe80::42/64    *  -\n\
             2026-11-12 09:35:00   52:54:00:aa:bb:cc   ipv4       192.168.221.42/24    *  -\n"
        );
        let leases = parse_dhcp_leases(&output);
        assert_eq!(leases.len(), 2);
        // The IPv6 row comes first, but a link-local address cannot be dialled without
        // a scope id, so the IPv4 lease must win.
        assert_eq!(
            lease_address_for(&leases, "52:54:00:aa:bb:cc").map(|ip| ip.to_string()),
            Some("192.168.221.42".to_string())
        );
    }

    #[test]
    fn test_lease_address_for_ignores_ipv6_only_and_other_macs() {
        let output = format!(
            "{LEASES_HEADER} 2026-11-12 09:35:00   52:54:00:aa:bb:cc   ipv6       fd00::42/64    *  -\n\
             2026-11-12 09:35:00   52:54:00:11:22:33   ipv4       192.168.221.43/24    *  -\n"
        );
        let leases = parse_dhcp_leases(&output);
        assert!(lease_address_for(&leases, "52:54:00:aa:bb:cc").is_none());
        assert!(lease_address_for(&leases, "52:54:00:de:ad:be").is_none());
        assert_eq!(
            lease_address_for(&leases, "52:54:00:11:22:33").map(|ip| ip.to_string()),
            Some("192.168.221.43".to_string())
        );
    }

    #[test]
    fn test_lease_address_for_prefers_the_newest_lease_of_one_mac() {
        // libvirt keeps the expiring row next to the renewed one; the older row is
        // listed first, so a first-match selector would dial an abandoned address.
        let output = format!(
            "{LEASES_HEADER} 2026-11-12 09:35:00   52:54:00:aa:bb:cc   ipv4       192.168.221.42/24    *  -\n\
             2026-11-12 10:05:00   52:54:00:aa:bb:cc   ipv4       192.168.221.77/24    *  -\n"
        );
        let leases = parse_dhcp_leases(&output);
        assert_eq!(leases.len(), 2);
        assert_eq!(leases[0].expiry, "2026-11-12 09:35:00");
        assert_eq!(leases[1].expiry, "2026-11-12 10:05:00");
        assert_eq!(
            lease_address_for(&leases, "52:54:00:aa:bb:cc").map(|ip| ip.to_string()),
            Some("192.168.221.77".to_string())
        );
    }

    #[test]
    fn test_production_code_never_awaits_a_command_without_a_budget() {
        // Every external command on the launch, teardown and network paths goes through
        // `bounded_output`, so a wedged child cannot outlive its budget. Written as a source
        // guard because the failing form compiles and looks innocuous in review.
        let sources = [
            ("machine.rs", include_str!("machine.rs")),
            ("utils.rs", include_str!("utils.rs")),
            ("windows.rs", include_str!("windows.rs")),
            ("qemu.rs", include_str!("qemu.rs")),
            ("firmware.rs", include_str!("firmware.rs")),
            ("qmp.rs", include_str!("qmp.rs")),
            ("ssh.rs", include_str!("ssh.rs")),
            ("pool.rs", include_str!("pool.rs")),
        ];
        // Split so this guard does not match itself.
        let unbounded = concat!(".output()", ".await");
        for (name, source) in sources {
            assert!(
                !source.contains(unbounded),
                "src/{name} awaits a child process without a budget; use `bounded_output`"
            );
        }
    }

    #[tokio::test]
    async fn test_run_bounded_separates_a_missing_program_from_a_hung_one() {
        // These two failures need opposite advice, so they must not arrive as one variant:
        // a missing program is installed, a hung one is waiting on something.
        let missing = run_bounded(
            tokio::process::Command::new("/nonexistent/qlean-probe"),
            std::time::Duration::from_secs(1),
            "probe",
        )
        .await
        .expect_err("a program that is not on PATH cannot produce output");
        assert!(
            matches!(missing, BoundedFailure::NotRun(_)),
            "expected NotRun, got {missing}"
        );

        let mut hung = tokio::process::Command::new("/bin/sleep");
        hung.arg("30");
        let killed = run_bounded(hung, std::time::Duration::from_millis(150), "probe")
            .await
            .expect_err("sleep 30 cannot answer inside 150ms");
        assert!(
            matches!(killed, BoundedFailure::Killed { .. }),
            "expected Killed, got {killed}"
        );
        assert!(killed.to_string().contains("/bin/sleep"), "{killed}");
    }

    #[test]
    fn test_program_problems_does_not_tell_the_user_to_reinstall_a_hung_program() {
        let probes = [(
            "virsh",
            ProgramProbe::Unusable(
                "`virsh` did not finish within 10s while trying to probe the program".to_string(),
            ),
        )];
        let problems = program_problems(&probes);
        assert_eq!(problems.len(), 1, "{problems:?}");
        let message = &problems[0];
        assert!(message.contains("`virsh`"), "{message}");
        assert!(message.contains("blocked"), "{message}");
        assert!(!message.contains("was not found"), "{message}");
        assert!(
            !message.contains("install it and try again"),
            "a hung program is already installed: {message}"
        );
    }

    #[tokio::test]
    async fn test_bounded_output_returns_a_finished_command() {
        let mut cmd = tokio::process::Command::new("/bin/echo");
        cmd.arg("hi");
        let output = bounded_output(cmd, std::time::Duration::from_secs(30), "echo")
            .await
            .expect("echo finishes well within the budget");
        assert!(output.status.success());
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "hi");
    }

    #[tokio::test]
    async fn test_bounded_output_kills_a_hung_command_at_the_deadline() {
        // A stuck child must not hang the caller forever: the budget has to end the wait,
        // name the program and say how long it waited.
        let mut cmd = tokio::process::Command::new("/bin/sleep");
        cmd.arg("30");
        let started = std::time::Instant::now();
        let error = bounded_output(
            cmd,
            std::time::Duration::from_millis(150),
            "prove the budget",
        )
        .await
        .expect_err("sleep 30 must not finish inside a 150ms budget")
        .to_string();
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "the budget must end the wait, took {:?}",
            started.elapsed()
        );
        assert!(error.contains("/bin/sleep"), "{error}");
        assert!(error.contains("150ms"), "{error}");
        assert!(error.contains("prove the budget"), "{error}");
        assert!(error.contains("killed"), "{error}");
    }

    #[test]
    fn test_lease_timeout_message_blames_libvirt_when_virsh_never_answered() {
        // The guest was never checked, so the message must not speculate about it.
        let message = lease_timeout_message(
            std::time::Duration::from_secs(300),
            "52:54:00:aa:bb:cc",
            &[],
            false,
            Some("error: failed to connect to the hypervisor"),
        );
        assert!(message.contains("never succeeded"), "{message}");
        assert!(
            message.contains("failed to connect to the hypervisor"),
            "{message}"
        );
        assert!(message.contains(VIRSH_CONNECTION_URI), "{message}");
        assert!(
            !message.contains("may still be booting"),
            "an unreachable libvirt must not be reported as a slow guest: {message}"
        );
    }

    #[test]
    fn test_lease_timeout_message_reports_the_leases_it_saw() {
        let leases = parse_dhcp_leases(&format!(
            "{LEASES_HEADER} 2026-11-12 09:35:00   52:54:00:11:22:33   ipv4       192.168.221.43/24    *  -\n"
        ));
        let message = lease_timeout_message(
            std::time::Duration::from_secs(900),
            "52:54:00:aa:bb:cc",
            &leases,
            true,
            None,
        );
        assert!(
            message.contains("no DHCP lease for MAC 52:54:00:aa:bb:cc"),
            "{message}"
        );
        assert!(message.contains("192.168.221.43"), "{message}");
        assert!(message.contains("900s"), "{message}");
        assert!(message.contains("virtio network device"), "{message}");
        assert!(!message.contains("last `virsh"), "{message}");
    }

    #[test]
    fn test_lease_timeout_message_keeps_a_failing_call_as_context() {
        let message = lease_timeout_message(
            std::time::Duration::from_secs(60),
            "52:54:00:aa:bb:cc",
            &[],
            true,
            Some("error: network 'qlean' not found"),
        );
        assert!(message.contains("may still be booting"), "{message}");
        assert!(
            message.contains(
                "last `virsh net-dhcp-leases` call failed: error: network 'qlean' not found"
            ),
            "{message}"
        );
    }

    #[test]
    fn test_parse_lease_expiry_ignores_rows_without_a_timestamp() {
        assert_eq!(
            parse_lease_expiry(" 2026-11-12 09:35:00   52:54:00:aa:bb:cc"),
            "2026-11-12 09:35:00"
        );
        assert_eq!(
            parse_lease_expiry("52:54:00:aa:bb:cc  ipv4  192.168.221.42/24"),
            ""
        );
        assert_eq!(parse_lease_expiry(""), "");
    }

    #[test]
    fn test_parse_lease_expiry_recognizes_a_lease_that_never_expires() {
        // `virsh` prints `infinite` for a static host entry. It is still a lease row, so it
        // must not be read as "no expiry at all".
        assert_eq!(
            parse_lease_expiry("infinite   52:54:00:aa:bb:cc   ipv4   192.168.221.42/24"),
            "infinite"
        );
        assert_eq!(parse_lease_expiry("Infinite"), "infinite");
    }

    #[test]
    fn test_lease_address_for_prefers_a_lease_that_never_expires() {
        // A reservation that never expires is the address the guest keeps; the expiring row
        // next to it is the one it abandoned. Ranking `infinite` as an empty string would
        // pick the abandoned address.
        let output = format!(
            "{LEASES_HEADER} 2026-11-12 09:35:00   52:54:00:aa:bb:cc   ipv4       192.168.221.42/24    *  -\n\
             infinite              52:54:00:aa:bb:cc   ipv4       192.168.221.77/24    *  -\n"
        );
        let leases = parse_dhcp_leases(&output);
        assert_eq!(leases.len(), 2);
        assert_eq!(leases[1].expiry, "infinite");
        assert_eq!(
            lease_address_for(&leases, "52:54:00:aa:bb:cc").map(|ip| ip.to_string()),
            Some("192.168.221.77".to_string())
        );
    }

    #[test]
    fn test_project_dir_or_explain_reports_an_unusable_environment() {
        // Mirrors `ProjectDirs::from("", "", "qlean")` returning `None` when neither
        // `XDG_DATA_HOME` nor `HOME` is usable.
        let err = project_dir_or_explain(None)
            .expect_err("no data directory must be an error, not a panic")
            .to_string();
        assert!(
            err.contains("cannot determine Qlean's data directory"),
            "{err}"
        );
        assert!(
            err.contains("XDG_DATA_HOME") && err.contains("HOME"),
            "{err}"
        );
    }

    #[test]
    fn test_create_dir_reports_an_uncreatable_path() {
        // A regular file as the parent makes `create_dir_all` fail with ENOTDIR.
        let root = std::env::temp_dir().join(format!(
            "qlean-create-dir-error-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&root, b"not a directory").unwrap();
        let child = root.join("nested");

        let err = create_dir("test", &child)
            .expect_err("a directory under a regular file cannot be created")
            .to_string();
        assert!(err.contains("failed to create the test directory"), "{err}");
        std::fs::remove_file(&root).unwrap();
    }

    #[test]
    fn test_path_argument_keeps_non_utf8_bytes_intact() {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};

        // A home directory that is not valid UTF-8, for example a byte from a legacy locale.
        let raw = std::ffi::OsString::from_vec(b"/home/l\xffgacy/seed/user-data".to_vec());
        let path = std::path::PathBuf::from(raw);
        let argument = path_argument("user-data=", &path);

        // `Path::display()` would replace `\xff` with U+FFFD here.
        assert!(path.to_string_lossy().contains('\u{fffd}'));
        let expected = b"user-data=/home/l\xffgacy/seed/user-data";
        assert_eq!(argument.as_os_str().as_bytes(), expected);
    }

    #[test]
    fn test_path_argument_prefixes_without_separator_side_effects() {
        let path = std::path::PathBuf::from("/run/qlean/abc/seed");
        let argument = path_argument("qlean=", &path);
        assert_eq!(
            argument,
            std::ffi::OsString::from("qlean=/run/qlean/abc/seed")
        );
        // An empty prefix yields the bare path.
        assert_eq!(
            path_argument("", &path),
            std::ffi::OsString::from("/run/qlean/abc/seed")
        );
    }

    #[test]
    fn test_program_problems_reports_every_gap_at_once() {
        let probes = [
            ("qemu-img", ProgramProbe::Available),
            (
                "virsh",
                ProgramProbe::Missing("No such file or directory (os error 2)".to_string()),
            ),
            (
                "xorriso",
                ProgramProbe::Broken("exit status: 1".to_string()),
            ),
        ];
        let problems = program_problems(&probes);
        assert_eq!(problems.len(), 2, "{problems:?}");
        assert!(problems[0].contains("`virsh`") && problems[0].contains("was not found"));
        assert!(problems[1].contains("`xorriso`") && problems[1].contains("looks broken"));
        // A missing program must not also be reported as broken, and vice versa.
        assert!(!problems[0].contains("looks broken"));
        assert!(!problems[1].contains("was not found"));
    }

    #[test]
    fn test_program_problems_is_empty_when_everything_is_available() {
        let probes = [
            ("qemu-img", ProgramProbe::Available),
            ("virsh", ProgramProbe::Available),
        ];
        assert!(program_problems(&probes).is_empty());
    }

    #[tokio::test]
    async fn test_check_commands_available_names_the_missing_program() {
        let problems = check_commands_available(&["qlean-definitely-not-installed"]).await;
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(
            problems[0].contains("qlean-definitely-not-installed"),
            "{problems:?}"
        );
        assert!(problems[0].contains("was not found"), "{problems:?}");
    }

    #[test]
    fn test_bridge_helper_path_prefers_a_known_install_path() {
        let found = bridge_helper_path(
            |candidate| candidate == Path::new("/usr/libexec/qemu-bridge-helper"),
            true,
        );
        assert_eq!(
            found.as_deref(),
            Some(Path::new("/usr/libexec/qemu-bridge-helper"))
        );
    }

    #[test]
    fn test_bridge_helper_path_falls_back_to_path_lookup() {
        assert_eq!(
            bridge_helper_path(|_| false, true).as_deref(),
            Some(Path::new("qemu-bridge-helper"))
        );
        assert_eq!(bridge_helper_path(|_| false, false), None);
    }

    #[test]
    fn test_bridge_helper_problem_explains_both_requirements() {
        assert!(
            bridge_helper_problem(Some(Path::new("/usr/lib/qemu/qemu-bridge-helper"))).is_none()
        );

        let problem = bridge_helper_problem(None).expect("a problem");
        // The binary is only half of it: the helper also needs the bridge allowlist.
        assert!(problem.contains("`qemu-bridge-helper`"), "{problem}");
        assert!(problem.contains("/etc/qemu/bridge.conf"), "{problem}");
        assert!(problem.contains("allow qlbr0"), "{problem}");
        // A `\`-continued literal swallows the newline but not stray indentation: keep the
        // message single-spaced so it reads as one paragraph.
        assert!(!problem.contains("  "), "{problem}");
    }

    #[test]
    fn test_create_dir_is_owner_only_even_with_a_permissive_umask() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "qlean-create-dir-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let existing = root.join("pre-existing");
        std::fs::create_dir_all(&existing).unwrap();
        std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o755)).unwrap();

        for path in [root.join("fresh"), existing.clone()] {
            create_dir("test", &path).unwrap();
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{path:?} should be 0700, got {mode:o}");
        }
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn test_parse_dhcp_leases_handles_ipv6_rows() {
        let output = format!(
            "{LEASES_HEADER} 2026-11-12 09:35:00   52:54:00:aa:bb:cc   ipv6       fd00::42/64    *  -\n"
        );
        let leases = parse_dhcp_leases(&output);
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].ip.to_string(), "fd00::42");
    }

    const QLEAN_NET_XML: &str = "\
<network connections='1'>
  <name>qlean</name>
  <uuid>8b2f1c26-0a5f-4a4f-9a1f-0b8f0a1f6d3c</uuid>
  <bridge name='qlbr0' stp='on' delay='0'/>
  <forward mode='nat'/>
  <ip address='192.168.221.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='192.168.221.2' end='192.168.221.254'/>
    </dhcp>
  </ip>
</network>
";

    #[test]
    fn existing_qlean_network_bridge_is_read_from_the_definition() {
        assert_eq!(network_bridge_name(QLEAN_NET_XML).as_deref(), Some("qlbr0"));
        assert_eq!(
            network_bridge_name("<network><bridge name=\"virbr7\"/></network>").as_deref(),
            Some("virbr7")
        );
    }

    #[test]
    fn a_network_without_a_bridge_element_is_not_guessed() {
        // `<name>` and `<uuid>` come first and must not be mistaken for the bridge.
        let xml = "<network><name>qlean</name><forward mode='nat'/></network>";
        assert_eq!(network_bridge_name(xml), None);
        assert_eq!(network_bridge_name("garbage"), None);
    }

    #[test]
    fn bridge_mismatch_names_both_bridges_and_the_recovery() {
        let message = bridge_mismatch_message("virbr0");
        assert!(message.contains("`virbr0`"), "{message}");
        assert!(message.contains(QLEAN_BRIDGE_NAME), "{message}");
        assert!(message.contains("net-undefine qlean"), "{message}");
    }

    fn virsh_output(code: i32, stdout: &str, stderr: &str) -> std::process::Output {
        use std::os::unix::process::ExitStatusExt;
        std::process::Output {
            status: std::process::ExitStatus::from_raw(code << 8),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    #[test]
    fn the_user_agent_follows_the_crate_version() {
        // A literal would drift at the next release and nobody would notice.
        assert_eq!(
            qlean_user_agent(),
            concat!("qlean/", env!("CARGO_PKG_VERSION"))
        );
        assert!(
            qlean_user_agent().starts_with("qlean/"),
            "{}",
            qlean_user_agent()
        );
    }

    #[test]
    fn a_failed_listing_is_an_error_not_an_empty_network_list() {
        // The exact mistake this guards: reading "virsh could not talk to libvirt" as
        // "the qlean network does not exist", which sends the user off to create it.
        let output = virsh_output(
            1,
            "",
            "error: failed to connect to the hypervisor\n\
             error: Failed to connect socket to '/run/libvirt/libvirt-sock': No such file or directory",
        );
        let error = listed_networks(&output, "net-list --all")
            .expect_err("a failed listing must not read as an empty list");
        let message = error.to_string();
        assert!(message.contains("libvirtd"), "{message}");
        assert!(message.contains(VIRSH_CONNECTION_URI), "{message}");
        assert!(message.contains("libvirt-sock"), "{message}");
    }

    #[test]
    fn a_listing_lists_networks_and_ignores_blank_lines() {
        let output = virsh_output(0, "default\nqlean\n\n", "");
        let networks = listed_networks(&output, "net-list --all").expect("a successful listing");
        assert!(networks.contains("qlean"), "{networks:?}");
        assert!(!networks.contains(""), "blank lines are not networks");
    }

    #[test]
    fn network_messages_have_no_runs_of_spaces() {
        // A lost `\` continuation left a long run of spaces in the bridge message; this is the
        // same guard the user-facing machine messages have.
        let failed = listed_networks(&virsh_output(1, "", "boom"), "net-list").unwrap_err();
        let messages = [
            bridge_assumed_message(),
            bridge_mismatch_message("virbr9"),
            failed.to_string(),
        ];
        for message in messages {
            for line in message.lines() {
                // Leading indentation is deliberate (it marks the commands to run); a run of
                // spaces *inside* a sentence is always a lost `\` continuation.
                assert!(
                    !line.trim_start().contains("  "),
                    "message line has a run of spaces: {line:?}"
                );
            }
        }
    }
}
