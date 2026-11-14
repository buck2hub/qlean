use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
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
    ///
    /// Kept as the `std::io::Error` rather than a formatted string because its
    /// [`std::io::ErrorKind`] is what separates "no such program" from "the program is
    /// here and the host refuses to run it": those two need opposite advice, and a string
    /// loses the distinction at the one place that still knows it (R215).
    NotRun(std::io::Error),
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
/// (and writing the file it was told to write) after the caller gave up. A real process
/// proves that in [`test_run_bounded_kills_the_child_it_gave_up_on`].
///
/// The kill reaches the child, not its children: a program that forks and exits leaves the
/// fork behind. Every program this runs (`virsh`, a `--version` probe, `qemu-img`,
/// `xorriso` in the tests) answers in its own process, so the group-kill that would be
/// needed for a forking program is not installed; a caller that ever runs one must say so
/// here instead of assuming the budget covers it.
pub(crate) async fn run_bounded(
    mut cmd: tokio::process::Command,
    budget: std::time::Duration,
    what: &str,
) -> std::result::Result<std::process::Output, BoundedFailure> {
    let program = cmd.as_std().get_program().to_string_lossy().into_owned();
    cmd.kill_on_drop(true);
    match tokio::time::timeout(budget, cmd.output()).await {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(error)) => Err(BoundedFailure::NotRun(error)),
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
                //
                // "Not available" covers two causes whose repairs have nothing in common, so
                // the cause decides the sentence: an installed client the host refuses to run
                // is not fixed by installing the package that shipped it (R215).
                if let Some(reason) = not_executable_reason(program, &error) {
                    bail!(
                        "no DHCP lease table can be read: {reason}.\n\
                         Windows guests discover their address through `{program} net-dhcp-leases`, \
                         so fix that file before starting a Windows guest"
                    );
                }
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
    create_owner_only_dir_all(path)
        .with_context(|| format!("failed to create the {purpose} directory {path:?}"))?;
    // Qlean's directories hold the client private key, per-VM host keys and seed media,
    // so they must not be traversable by other local users even when the umask allows it.
    // Creation already applies 0700; this also tightens a directory that existed before.
    restrict_dir(path)
}

/// A path that travels *inside* a `key=value` option list, checked before it is embedded.
///
/// QEMU and `swtpm` both split an option list on commas, so a comma in the path ends the value
/// early and the rest of the path is read as further options. Measured against `swtpm` 0.10.2
/// (R239): `--tpmstate dir=/t/a,b/tpm` dies with `swtpm: Error parsing tpmstate options:
/// Unknown option 'b/tpm'`, and `--log file=/t/a,b/ok.log,level=1` with `Error parsing logging
/// options: Unknown option 'b/ok.log'` - both name a fragment of the path, neither names the
/// comma. A reader then has a fragment to explain and nothing that says which field was wrong.
///
/// So the value is refused before either tool sees it, and refused by the *same* rule for both,
/// because "which characters end an option value" is one fact: two answers to it is how the
/// QEMU argument builder came to reject a comma while the `swtpm` one handed it over. A space is
/// fine - the value travels as a single argv element.
pub(crate) fn option_field_text(kind: &str, path: &Path) -> Result<String> {
    let text = path.to_string_lossy().into_owned();
    if text.is_empty() {
        bail!("{kind} path is empty");
    }
    if text.contains(',') {
        bail!(
            "{kind} path `{text}` contains a comma, which QEMU and `swtpm` read as a separator \
             between options, so the value would end mid-path and the rest would be read as \
             unknown options; move it to a path without commas"
        );
    }
    if text.chars().any(char::is_control) {
        bail!(
            "{kind} path `{text}` contains a control character, which splits the option list \
             or the line that records it"
        );
    }
    Ok(text)
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

/// Create a directory path with owner-only permission **at creation time**.
///
/// The directory counterpart of [`create_owner_only`]: `create_dir_all` plus a `chmod` opens
/// exactly the window R97 closed for files — the tree exists with the umask's permissions
/// (0755 under the usual 022) until the `chmod` runs, and that window holds whatever the
/// caller writes into it next (a private key, TPM state, a seed medium) as well as the
/// directory itself. `DirBuilder::mode` applies the mode to every level it creates, so no
/// umask can widen the result; directories that already exist are left alone (call
/// [`restrict_dir`] for those).
pub(crate) fn create_owner_only_dir_all(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;

        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)
    }
}

/// Create `path` with owner-only permission **at creation time**.
///
/// `chmod` after the write is a different program: between the two calls the file exists on
/// disk with the umask's permissions (0644 under the usual 022), and a crash or a failed
/// `chmod` leaves it that way for good. Creating it with `0600` means no umask can widen it
/// and no window exists at all.
pub(crate) fn create_owner_only(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

/// Temporary file one write stages its bytes in before the rename.
///
/// The name carries the writing process and a per-write counter, because the destination alone
/// is not enough to identify a write: two pooled machines initialized at the same time ask for
/// the same shared client key, and with a temporary name derived from the destination the
/// second write removed the first one's staging file and installed its own bytes at the final
/// path. The first machine then held a key in memory whose other half was never on disk, and
/// the installed credential could be a file that was still being written. The leading dot
/// keeps a crash's leftover out of the way, and the name stays next to its destination so the
/// rename never crosses a filesystem.
fn temp_owner_only_path(path: &Path) -> PathBuf {
    static WRITES: AtomicU64 = AtomicU64::new(0);
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "credential".to_string());
    path.with_file_name(format!(
        ".{name}.{}-{}.tmp",
        std::process::id(),
        WRITES.fetch_add(1, Ordering::Relaxed)
    ))
}

/// Write `contents` to `path` owner-only and atomically.
///
/// The file is created with [`create_owner_only`], its bytes are synced to the disk, and only
/// then is it renamed into place; the directory is synced afterwards. That is what makes the
/// promise true: a crash leaves either the previous file or a complete one — never a partial
/// credential that still parses as "some file", and never a complete one that others can read.
/// Without the two syncs the claim was about the *name* only: `write_all` hands the bytes to the
/// page cache, so a power cut between the write and the next write-back could publish a
/// credential that is complete by name and empty (or half) by content. Each write stages its
/// bytes in a temporary file of its own, so two writers can never install each other's half.
pub(crate) fn write_owner_only_atomically(path: &Path, contents: &str) -> Result<()> {
    let tmp_path = temp_owner_only_path(path);
    // A write that was interrupted between the create and the rename leaves this name behind;
    // the counter makes it unique to that write, so whatever is here is a leftover.
    let _ = std::fs::remove_file(&tmp_path);
    let mut tmp = create_owner_only(&tmp_path).with_context(|| {
        format!(
            "failed to create the temporary file {} with owner-only permissions",
            tmp_path.display()
        )
    })?;
    let written = std::io::Write::write_all(&mut tmp, contents.as_bytes())
        .and_then(|()| std::io::Write::flush(&mut tmp))
        // The bytes have to be on the disk before the name is published: `flush` only pushes
        // them out of this process, and the rename below makes them reachable under the real
        // name whether or not they ever left the page cache.
        .and_then(|()| tmp.sync_all())
        .with_context(|| format!("failed to write {}", tmp_path.display()));
    drop(tmp);
    if let Err(error) = written {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(error);
    }
    std::fs::rename(&tmp_path, path).with_context(|| {
        format!(
            "failed to install {} (the complete file is left at {})",
            path.display(),
            tmp_path.display()
        )
    })?;
    // The rename is a directory entry, and a directory entry is only durable once the
    // directory is: without this a crash can still find the previous file - or no file - at a
    // name the caller was told had been written.
    sync_directory_of(path).with_context(|| {
        format!(
            "wrote {} but could not make its directory durable",
            path.display()
        )
    })?;
    Ok(())
}

/// Flush a directory's entries to the disk, so a rename inside it survives a crash.
pub(crate) fn sync_directory_of(path: &Path) -> std::io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    let directory = parent.unwrap_or_else(|| Path::new("."));
    std::fs::File::open(directory)?.sync_all()
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

/// The first CID handed out, when no run directory has claimed one yet.
const FIRST_GUEST_CID: u32 = 10;

/// The highest CID a guest may be given.
///
/// Linux reserves the low values (`0` hypervisor, `1` local, `2` host) and `u32::MAX`
/// (`VMADDR_CID_ANY`), so the last usable CID is one below the ceiling.
const LAST_GUEST_CID: u32 = u32::MAX - 1;

/// Hand out a guest CID that no live run directory has claimed.
///
/// The allocation is "the highest `cid` under the runs directory, plus one". A `cid` file is
/// written by Qlean itself, but it lives in a directory a caller can copy, restore or edit, so
/// the value is untrusted input: at the ceiling, `+ 1` panics in a debug build and wraps to `0`
/// (a reserved CID the host cannot reach) in a release build. Both are refused here instead.
pub(crate) fn get_free_cid(runs_dir: &Path, run_dir: &Path) -> Result<u32> {
    let mut cids = vec![];

    let runs_dir = runs_dir.to_owned();
    let run_dir = run_dir.to_owned();

    let lock_dir = runs_dir.join("lockdir");
    trace!("Trying to lock {lock_dir:?}");
    let lock = DirLock::new_sync(&lock_dir)?;

    for entry in WalkDir::new(&runs_dir) {
        let entry = entry?;
        let filename = entry.file_name();
        if filename.to_string_lossy() == "cid" {
            trace!("Found CID file at {:?}", entry.path());
            let cid = std::fs::read_to_string(entry.path())?;
            cids.push(cid.trim().parse::<u32>().with_context(|| {
                format!(
                    "failed to read the guest CID recorded in {}",
                    entry.path().display()
                )
            })?);
        }
    }

    // Get the next CID.
    cids.sort();
    let cid = if let Some(last_cid) = cids.iter().next_back() {
        last_cid
            .checked_add(1)
            .filter(|cid| *cid <= LAST_GUEST_CID)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "cannot allocate a guest CID: the run directories under {} already use {last_cid}, \
                     and a guest may not be given a CID above {LAST_GUEST_CID}. Remove the run \
                     directories of machines that no longer exist and retry.",
                    runs_dir.display()
                )
            })?
    } else {
        // Nothing has claimed a CID yet, so start at an arbitrary value above the reserved ones.
        FIRST_GUEST_CID
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

/// Whether `path` is a regular file the host can actually execute.
///
/// The single definition of "executable" in this crate: the Windows prerequisite gate
/// (`crate::firmware::executable_file`) delegates here, because two answers to "can this
/// program run?" is how one gate accepts a file the other one rejects.
pub(crate) fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
}

/// The file a bare program name resolves to when it exists but cannot be executed.
///
/// Only used to name the file in an error message: the probe itself still runs the program,
/// which is the only way to learn that a *working* installation really works.
fn unexecutable_on_path(program: &str) -> Option<PathBuf> {
    if program.contains('/') {
        let path = Path::new(program);
        return (path.is_file() && !is_executable_file(path)).then(|| path.to_path_buf());
    }
    let paths = std::env::var_os("PATH")?;
    std::env::split_paths(&paths)
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file() && !is_executable_file(candidate))
}

/// Why a program that could not be started is installed-but-unrunnable, if it is.
///
/// `NotFound` and `PermissionDenied` arrive as one failure shape ("the program never ran"),
/// and this is the one place that tells them apart, for both gates. Returns `None` for every
/// other start failure, whose message belongs to the caller.
///
/// The wording may not say "not found" or "install it": the sentence is read by someone who
/// already has the package, and telling them to install it again is what made the gate
/// useless (R215).
pub(crate) fn not_executable_reason(program: &str, error: &std::io::Error) -> Option<String> {
    if error.kind() != std::io::ErrorKind::PermissionDenied {
        return None;
    }
    let file = unexecutable_on_path(program)
        .map(|path| format!(" at {}", path.display()))
        .unwrap_or_default();
    Some(format!(
        "`{program}` is installed{file} but cannot be executed ({error}): check that file's \
         permissions and that its filesystem is not mounted `noexec`"
    ))
}

/// How probing one required program turned out.
#[derive(Debug)]
enum ProgramProbe {
    /// The program answered `--version`.
    Available,
    /// Nothing by that name exists.
    Missing(String),
    /// The program exists but the host refuses to execute it.
    NotExecutable(String),
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
            // The reason already names the program, the file and the two repairs that fit an
            // installed-but-unrunnable program; adding "install it" here is what contradicted
            // the parenthetical it is printed next to (R215).
            ProgramProbe::NotExecutable(reason) => Some(reason.clone()),
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
            Err(BoundedFailure::NotRun(error)) => match not_executable_reason(program, &error) {
                Some(reason) => ProgramProbe::NotExecutable(reason),
                None => ProgramProbe::Missing(error.to_string()),
            },
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

    /// A `cid` file at the ceiling must be refused, not incremented into a reserved value.
    ///
    /// `get_free_cid` allocates by reading the highest `cid` under the runs directory and adding
    /// one, and the file it reads lives in a directory a caller can copy or restore. At the
    /// ceiling the addition itself is the bug: a debug build panics inside the library, and a
    /// release build wraps to `0` - a reserved CID - so the guest boots with a number the host
    /// cannot dial. Nothing here needs a guest, a QEMU or a network, which is why the file-system
    /// half of the allocation can be tested where every round runs.
    #[test]
    fn test_a_cid_at_the_ceiling_is_refused_instead_of_overflowing() {
        let runs = tempfile::tempdir().expect("temp dir");
        let run = runs.path().join("run-1");
        std::fs::create_dir_all(&run).expect("run dir");
        std::fs::write(run.join("cid"), LAST_GUEST_CID.to_string()).expect("cid file");

        let error = get_free_cid(runs.path(), &run).expect_err("the ceiling has no next CID");
        let message = error.to_string();
        assert!(
            message.contains("cannot allocate a guest CID"),
            "the refusal must name itself: {message}"
        );
        assert!(
            message.contains("Remove the run directories"),
            "the refusal must say what to do about it: {message}"
        );
        assert_eq!(
            std::fs::read_to_string(run.join("cid")).expect("the cid file"),
            LAST_GUEST_CID.to_string(),
            "a refused allocation must not rewrite the `cid` file"
        );

        // The ceiling itself is also out of range: `u32::MAX` is `VMADDR_CID_ANY`. The addition
        // would overflow here in a debug build, so this is the case the pre-fix code panicked on.
        std::fs::write(run.join("cid"), u32::MAX.to_string()).expect("cid file");
        let error = get_free_cid(runs.path(), &run).expect_err("u32::MAX is not a guest CID");
        assert!(
            error.to_string().contains("cannot allocate a guest CID"),
            "a reserved CID must be refused, not wrapped: {error}"
        );
    }

    /// The happy paths of the allocation, so the guard above is not the only thing exercising it.
    #[test]
    fn test_the_next_cid_follows_the_highest_one_and_starts_above_the_reserved_range() {
        let runs = tempfile::tempdir().expect("temp dir");
        let first = runs.path().join("run-1");
        std::fs::create_dir_all(&first).expect("run dir");

        let cid = get_free_cid(runs.path(), &first).expect("the first allocation");
        assert_eq!(cid, FIRST_GUEST_CID, "an empty runs directory starts at 10");
        assert_eq!(
            std::fs::read_to_string(first.join("cid")).expect("the cid file"),
            cid.to_string(),
            "the allocation is recorded in the run directory"
        );

        // A second machine, and one whose run directory is nested deeper: the walk is recursive,
        // so a `cid` file under a nested path still counts as claimed.
        let second = runs.path().join("run-2");
        let nested = runs.path().join("run-2").join("seed");
        std::fs::create_dir_all(&nested).expect("nested dir");
        std::fs::write(nested.join("cid"), (FIRST_GUEST_CID + 4).to_string()).expect("cid file");
        let cid = get_free_cid(runs.path(), &second).expect("the second allocation");
        assert_eq!(
            cid,
            FIRST_GUEST_CID + 5,
            "the highest recorded CID wins, wherever it is nested"
        );
    }

    /// A `cid` file nobody can parse is reported with the file it came from.
    #[test]
    fn test_an_unparsable_cid_names_the_file_it_came_from() {
        let runs = tempfile::tempdir().expect("temp dir");
        let run = runs.path().join("run-1");
        std::fs::create_dir_all(&run).expect("run dir");
        std::fs::write(run.join("cid"), "not-a-number").expect("cid file");

        let error = get_free_cid(runs.path(), &run).expect_err("garbage is not a CID");
        let message = format!("{error:#}");
        assert!(
            message.contains("failed to read the guest CID recorded in"),
            "the error must say what it was reading: {message}"
        );
        assert!(
            message.contains("run-1"),
            "the error must point at the offending run directory: {message}"
        );
    }

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

    /// R215: the lease lookup separates "no lease tool" from "a tool the host will not run".
    #[tokio::test]
    async fn test_a_lease_tool_that_cannot_be_executed_keeps_its_own_advice() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("temp dir");
        let program = root.path().join("virsh");
        std::fs::write(&program, b"#!/bin/sh\nexit 0\n").expect("write");
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let name = program.display().to_string();

        let start = std::time::Instant::now();
        let error = find_lease_address_with(
            "52:54:00:aa:bb:cc",
            std::time::Duration::from_secs(30),
            &name,
        )
        .await
        .expect_err("a program without an execute bit cannot answer");
        let elapsed = start.elapsed();
        let message = format!("{error:#}");

        assert!(
            message.contains(&name),
            "the file to fix must be named: {message}"
        );
        assert!(
            message.contains("cannot be executed") && message.contains("noexec"),
            "an installed client is a permissions problem: {message}"
        );
        assert!(
            !message.contains("install the `libvirt` package"),
            "installing libvirt again is the wrong repair: {message}"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "waited {elapsed:?} for a program that cannot be executed"
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

    /// Whether `pid` is still a live process (a zombie is dead, only not yet reaped).
    fn still_alive(pid: i32) -> bool {
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            return false;
        };
        // `/proc/<pid>/stat` is `pid (comm) STATE ...`, and `comm` may contain spaces and
        // parentheses, so the state is the field right after the *last* `)`.
        let Some(close) = stat.rfind(')') else {
            return false;
        };
        let state = stat[close + 1..].split_whitespace().next();
        !matches!(state, Some("Z") | Some("X"))
    }

    #[tokio::test]
    async fn test_run_bounded_kills_the_child_it_gave_up_on() {
        // "Killed" is the whole point of the budget: a program that keeps running after the
        // caller gave up still holds whatever it was writing (a seed ISO, a qcow2 overlay),
        // and the next run trips over it. Only a real process can prove that, so the child
        // records its own pid (`exec` keeps that pid the one that runs) and the pid must be
        // gone afterwards.
        let tmp = tempfile::tempdir().expect("temp dir");
        let pid_file = tmp.path().join("pid");
        let mut hung = tokio::process::Command::new("/bin/sh");
        hung.arg("-c")
            .arg(format!("echo $$ > {}; exec sleep 30", pid_file.display()));
        let failure = run_bounded(hung, std::time::Duration::from_millis(150), "probe")
            .await
            .expect_err("sleep 30 cannot answer inside 150ms");
        assert!(
            matches!(failure, BoundedFailure::Killed { .. }),
            "expected Killed, got {failure}"
        );

        let pid = std::fs::read_to_string(&pid_file).expect("the child recorded its own pid");
        let pid: i32 = pid.trim().parse().expect("a pid");
        // The kill is a signal and the reap happens in the background, so give it a moment.
        let mut alive = still_alive(pid);
        for _ in 0..40 {
            if !alive {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            alive = still_alive(pid);
        }
        assert!(
            !alive,
            "`{pid}` was still running a second after the budget expired: the message says \
             the process was killed, so it has to be"
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

#[cfg(test)]
mod owner_only_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).expect("stat").permissions().mode() & 0o777
    }

    #[test]
    fn test_the_file_is_owner_only_from_the_moment_it_exists() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("secret");
        write_owner_only_atomically(&path, "material").expect("written");
        assert_eq!(mode_of(&path), 0o600);
        assert_eq!(std::fs::read_to_string(&path).expect("read"), "material");
        // No temporary file survives a successful install.
        assert_eq!(
            std::fs::read_dir(dir.path()).expect("read dir").count(),
            1,
            "a temporary file survived the install"
        );
    }

    /// Each write stages its bytes in a temporary file of its own.
    ///
    /// The name used to come from the destination alone (`with_extension("tmp")`), so two
    /// writers of the same file shared one staging path: the second removed the first's file,
    /// wrote its own bytes there, and the first then renamed the *second* writer's half-written
    /// file into place. Two writes must not be able to address the same temporary file, and
    /// files that only share a stem (`deploy.json`, `deploy.iso`) must not collide either.
    #[test]
    fn test_each_write_stages_its_bytes_in_its_own_temporary_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let first = dir.path().join("id_ed25519");

        let one = temp_owner_only_path(&first);
        let two = temp_owner_only_path(&first);
        assert_ne!(one, two, "two writes shared one temporary file");
        for tmp in [&one, &two] {
            assert_eq!(tmp.parent(), first.parent(), "the rename must stay put");
            assert_ne!(tmp, &first, "a write must not stage over its destination");
            let name = tmp
                .file_name()
                .and_then(|name| name.to_str())
                .expect("the temporary file has a UTF-8 name");
            let name = name.strip_prefix('.').unwrap_or(name);
            assert!(
                name.starts_with("id_ed25519") && name.ends_with(".tmp"),
                "the temporary file must name the file it belongs to: {tmp:?}"
            );
        }

        let json = temp_owner_only_path(&dir.path().join("deploy.json"));
        let iso = temp_owner_only_path(&dir.path().join("deploy.iso"));
        assert_ne!(
            json, iso,
            "two files that share a stem must not share a temporary file"
        );
    }

    /// Concurrent writers of one file never install a partial or mixed file.
    ///
    /// This is the race the unique temporary name exists for: every call must succeed, and the
    /// file that ends up on disk must be exactly one of the contents, complete.
    #[test]
    fn test_concurrent_writes_install_one_complete_file() {
        use std::sync::{Arc, Barrier};

        const WRITERS: usize = 8;
        const ROUNDS: usize = 20;

        let dir = tempfile::tempdir().expect("temp dir");
        let path = Arc::new(dir.path().join("id_ed25519"));
        let barrier = Arc::new(Barrier::new(WRITERS));
        let contents: Vec<String> = (0..WRITERS)
            .map(|writer| format!("{writer:02}").repeat(4096))
            .collect();

        let handles: Vec<_> = contents
            .iter()
            .cloned()
            .map(|body| {
                let path = Arc::clone(&path);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let mut results = Vec::new();
                    for _ in 0..ROUNDS {
                        barrier.wait();
                        results.push(write_owner_only_atomically(&path, &body));
                    }
                    results
                })
            })
            .collect();

        for handle in handles {
            for result in handle.join().expect("writer thread") {
                result.expect("a concurrent write must not fail");
            }
        }

        let installed = std::fs::read_to_string(path.as_ref()).expect("read");
        assert!(
            contents.contains(&installed),
            "the installed file is not one complete writer's contents: {} bytes",
            installed.len()
        );
        assert_eq!(mode_of(path.as_ref()), 0o600);
        assert_eq!(
            std::fs::read_dir(dir.path()).expect("read dir").count(),
            1,
            "a temporary file survived the concurrent writes"
        );
    }

    /// The credential is only "complete" once its bytes and its name are on the disk.
    ///
    /// The doc comment promised "never a partial credential that still parses as some file"
    /// while the write only reached the page cache: `write_all` + `flush` say nothing about the
    /// disk, so a crash between them and the next write-back could publish a file that is
    /// complete by name and empty by content. The order is the whole contract, so it is checked
    /// as an order and not as two independent facts.
    #[test]
    fn the_credential_reaches_the_disk_before_its_name_is_published() {
        const SOURCE: &str = include_str!("utils.rs");
        let start = SOURCE
            .find("pub(crate) fn write_owner_only_atomically(")
            .expect("the credential write is gone");
        let body = &SOURCE[start..];
        let body = &body[..body.find("\n}\n").expect("the write has no end")];

        let written = body.find("write_all(&mut tmp").expect("no write");
        let synced = body
            .find("tmp.sync_all()")
            .expect("the staged bytes are never synced, so the rename publishes whatever the page cache holds");
        let renamed = body.find("std::fs::rename(").expect("no rename");
        // The call has to be propagated, not merely present: an ignored result reports a
        // durable rename that nobody vouched for (a mutation showed the difference).
        let directory = body.find("sync_directory_of(path).with_context(").expect(
            "the rename is never made durable, so a crash can still find the previous file",
        );
        assert!(
            body[directory..].contains("})?;"),
            "the directory sync reports a durability nobody confirmed"
        );
        assert!(
            written < synced && synced < renamed,
            "the file must be synced between the write and the rename: write at {written}, \
             sync at {synced}, rename at {renamed}"
        );
        assert!(
            renamed < directory,
            "the directory has to be synced after the rename, not before it"
        );
        // A staging file that is not synced is not staged: the helper must be the one that
        // creates it owner-only, and `sync_all` must follow the same handle.
        assert!(
            body.contains("create_owner_only(&tmp_path)"),
            "the staged file is no longer created owner-only"
        );
    }

    /// A staging file whose directory cannot be synced is reported, not assumed durable.
    #[test]
    fn a_rename_nobody_could_make_durable_is_reported() {
        let dir = tempfile::tempdir().expect("temp dir");
        // `sync_directory_of` is what the write calls; a path without a parent has to fall back
        // to the current directory instead of silently skipping the sync.
        assert!(sync_directory_of(&dir.path().join("secret")).is_ok());
        assert!(sync_directory_of(Path::new("relative-name")).is_ok());
    }

    #[test]
    fn test_the_contents_replace_the_previous_file_only_when_complete() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("secret");
        write_owner_only_atomically(&path, "old").expect("written");
        write_owner_only_atomically(&path, "new").expect("rewritten");
        assert_eq!(std::fs::read_to_string(&path).expect("read"), "new");
        assert_eq!(mode_of(&path), 0o600);
    }

    /// A directory that cannot be written is the cheapest way to reach the failure path: the
    /// temporary file must not survive it.
    #[test]
    fn test_a_failed_write_leaves_no_temporary_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let missing = dir.path().join("absent").join("secret");
        assert!(write_owner_only_atomically(&missing, "material").is_err());
        assert!(
            std::fs::read_dir(dir.path())
                .expect("read dir")
                .next()
                .is_none(),
            "a failed write left something behind"
        );
    }

    /// `chmod` after the write is a different program: the mode has to come from creation,
    /// and the write has to be atomic, or a crash leaves a readable or truncated credential.
    #[test]
    fn test_owner_only_files_are_created_that_way_and_never_chmoded() {
        fn region<'a>(source: &'a str, from: &str, to: &str) -> &'a str {
            let start = source.find(from).expect("region start");
            let rest = &source[start..];
            let end = rest.find(to).expect("region end");
            &rest[..end]
        }

        let source = include_str!("utils.rs");
        let writer = region(
            source,
            "pub(crate) fn create_owner_only",
            "pub(crate) fn restrict_file",
        );
        assert!(
            !writer.contains("set_permissions") && !writer.contains("set_mode"),
            "the mode must come from `OpenOptions::mode`, not from a `chmod` that leaves a \
             window (and a crash) with the umask's permissions"
        );
        assert_eq!(
            writer.matches("0o600").count(),
            1,
            "`0o600` must appear exactly once in the writer, in the file creation call"
        );
        assert!(
            writer.contains(".mode(0o600)"),
            "the file must be created with `OpenOptionsExt::mode(0o600)`"
        );
        assert!(
            writer.contains("std::fs::rename(&tmp_path, path)"),
            "the file must be installed by a rename so a crash cannot leave a partial file"
        );

        // Every credential Qlean writes has to go through it.
        let ssh = include_str!("ssh.rs");
        let generator = region(
            ssh,
            "pub(crate) fn generate_keypair",
            "#[derive(Debug, Clone, Default)]",
        );
        assert!(
            generator.contains("write_owner_only_atomically(privkey_path"),
            "`generate_keypair` must write the private key through `write_owner_only_atomically`"
        );
        let windows = include_str!("windows.rs");
        let staging = region(
            windows,
            "pub(crate) async fn stage",
            "pub(crate) async fn build",
        );
        assert!(
            staging.contains("write_owner_only_atomically(&host_key_path"),
            "the staged host private key must be written through `write_owner_only_atomically`"
        );
        assert!(
            staging
                .split("ssh_host_ed25519_key")
                .nth(1)
                .is_some_and(|after| after.contains("write_owner_only_atomically")),
            "the staged host private key must not be written with a plain write plus `chmod`"
        );
    }

    /// A directory that will hold secrets has to be restricted when it is created.
    ///
    /// `create_dir_all` plus `chmod` is the same two-step the file writer was fixed for: for
    /// as long as the `chmod` has not run, the directory exists with the umask's permissions,
    /// and the caller writes the private key, the seed medium or the TPM state into it right
    /// afterwards. The end state looks identical, so only creation can be inspected.
    #[test]
    fn test_owner_only_directories_are_created_that_way_and_never_chmoded() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("temp dir");
        let nested = dir.path().join("a").join("b");
        create_owner_only_dir_all(&nested).expect("nested directory");
        assert!(nested.is_dir(), "the helper must create parents too");
        for path in [nested.clone(), dir.path().join("a")] {
            let mode = std::fs::metadata(&path)
                .expect("created dir")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o700, "{} came out as {mode:o}", path.display());
        }

        fn region<'a>(source: &'a str, from: &str, to: &str) -> &'a str {
            let start = source.find(from).expect("region start");
            let rest = &source[start..];
            let end = rest.find(to).expect("region end");
            &rest[..end]
        }

        let source = include_str!("utils.rs");
        let helper = region(
            source,
            "pub(crate) fn create_owner_only_dir_all",
            "pub(crate) fn create_owner_only(",
        );
        assert!(
            helper.contains(".mode(0o700)"),
            "the directory must be created with `DirBuilderExt::mode(0o700)`"
        );
        assert!(
            !helper.contains("set_permissions") && !helper.contains("set_mode"),
            "the mode must come from creation, not from a `chmod` that leaves a window"
        );

        // Every directory Qlean fills with secrets has to go through it.
        let firmware = include_str!("firmware.rs");
        let tpm = region(
            firmware,
            "let state_dir = run_dir.join(\"tpm\")",
            "let socket =",
        );
        assert!(
            tpm.contains("create_owner_only_dir_all(&state_dir)"),
            "the per-VM TPM state dir must be created owner-only"
        );
        assert!(
            !tpm.contains("set_permissions"),
            "the per-VM TPM state dir must not be `chmod`ed after creation"
        );

        let machine = include_str!("machine.rs");
        let run_dir = region(
            machine,
            "let seed_dir = run_dir.join(\"seed\")",
            "RunDirGuard::new",
        );
        assert!(
            run_dir.contains("create_owner_only_dir_all(&run_dir)")
                && run_dir.contains("create_owner_only_dir_all(&seed_dir)"),
            "the run directory and its seed directory must be created owner-only"
        );
        assert!(
            !run_dir.contains("create_dir_all(&run_dir)"),
            "the run directory must not be created with the umask's permissions"
        );

        // The invariant had two more call sites and this guard read neither of them: the
        // Windows branch of `launch` (which creates the run directory that is about to receive
        // the TPM state) and the seed root the deployment medium is built from (which receives
        // the guest's SSH host private key). Same rule, same two assertions.
        let launch = region(
            machine,
            "let run_dir = dirs.runs.join(&self.id);",
            "let resolved = firmware::resolve_ovmf()?;",
        );
        assert!(
            launch.contains("create_owner_only_dir_all(&run_dir)"),
            "the Windows launch path must create the run directory owner-only"
        );
        assert!(
            !launch.contains("create_dir_all(&run_dir)"),
            "the Windows launch path creates the run directory with the umask's permissions"
        );

        let windows = include_str!("windows.rs");
        let seed_root = region(
            windows,
            "let root = dir.join(SEED_ROOT);",
            "let authorized_keys =",
        );
        assert!(
            seed_root.contains("create_owner_only_dir_all(&root)"),
            "the seed root the host private key is written into must be created owner-only"
        );
        assert!(
            !seed_root.contains("create_dir_all(&root)"),
            "the seed root is created with the umask's permissions before a `chmod` closes them"
        );
    }
    /// R215: an installed program the host refuses to execute is not a missing package.
    #[tokio::test]
    async fn test_an_unexecutable_program_is_reported_as_unrunnable() {
        let root = tempfile::tempdir().expect("temp dir");
        let program = root.path().join("qemu-img");
        std::fs::write(&program, b"#!/bin/sh\nexit 0\n").expect("write");
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o644))
            .expect("chmod 0644");

        // The probe fails the same way the gate used to misread: `spawn` answers EACCES.
        let refusal = std::process::Command::new(&program)
            .arg("--version")
            .output()
            .expect_err("0644 is not executable");
        assert_eq!(refusal.kind(), std::io::ErrorKind::PermissionDenied);

        let name: &'static str = Box::leak(program.display().to_string().into_boxed_str());
        let problems = check_commands_available(&[name]).await;
        assert_eq!(problems.len(), 1, "one program, one problem: {problems:#?}");
        let problem = &problems[0];
        assert!(
            problem.contains("is installed") && problem.contains("cannot be executed"),
            "the message must name the cause: {problem}"
        );
        assert!(
            problem.contains(&program.display().to_string()),
            "the message must name the file: {problem}"
        );
        assert!(
            problem.contains("noexec"),
            "the message must name the mount option that causes this: {problem}"
        );
        assert!(
            !problem.contains("was not found") && !problem.contains("install it"),
            "a program that is present must not be reported as absent: {problem}"
        );
    }

    /// The other half of the same distinction: absence keeps its own remedy.
    #[tokio::test]
    async fn test_a_program_that_is_absent_is_still_reported_as_missing() {
        let problems = check_commands_available(&["/nonexistent/qlean-probe"]).await;
        assert_eq!(problems.len(), 1, "{problems:#?}");
        let problem = &problems[0];
        assert!(
            problem.contains("was not found") && problem.contains("install it and try again"),
            "absence is a missing package: {problem}"
        );
        assert!(
            !problem.contains("cannot be executed"),
            "absence is not a permissions problem: {problem}"
        );
    }

    /// The classification is one decision, so it is testable without spawning anything.
    #[test]
    fn test_only_a_permission_refusal_counts_as_an_unrunnable_program() {
        let denied = std::io::Error::from_raw_os_error(13);
        let reason = not_executable_reason("qemu-img", &denied).expect("EACCES is a refusal");
        assert!(
            reason.contains("cannot be executed") && reason.contains("qemu-img"),
            "the reason names the program and the cause: {reason}"
        );
        assert!(
            !reason.contains("was not found") && !reason.contains("install it"),
            "the reason may not borrow the missing program's advice: {reason}"
        );
        for other in [2, 20] {
            let error = std::io::Error::from_raw_os_error(other);
            assert!(
                not_executable_reason("qemu-img", &error).is_none(),
                "os error {other} is not a refusal to execute: {error}"
            );
        }
        assert!(
            not_executable_reason(
                "qemu-img",
                &std::io::Error::from(std::io::ErrorKind::NotFound)
            )
            .is_none()
        );
    }

    /// `is_executable_file` is the crate's only definition of "this program can run".
    #[test]
    fn test_executable_file_wants_a_regular_file_with_an_execute_bit() {
        let root = tempfile::tempdir().expect("temp dir");
        let plain = root.path().join("plain");
        std::fs::write(&plain, b"").expect("write");
        std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o644))
            .expect("chmod 0644");
        assert!(!is_executable_file(&plain));
        std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o755))
            .expect("chmod 0755");
        assert!(is_executable_file(&plain));
        assert!(
            !is_executable_file(root.path()),
            "a directory is not a program"
        );
        assert!(
            !is_executable_file(&root.path().join("absent")),
            "nothing there is not a program"
        );
    }

    /// One program, one line, whichever cause it was: no cause may collect two.
    #[test]
    fn test_each_failing_program_produces_exactly_one_line() {
        let probes = [
            (
                "/usr/bin/qemu-img",
                ProgramProbe::NotExecutable("denied".into()),
            ),
            (
                "/usr/bin/virsh",
                ProgramProbe::Missing("no such file".into()),
            ),
        ];
        let problems = program_problems(&probes);
        assert_eq!(problems, vec!["denied".to_string(), "`/usr/bin/virsh` is required but was not found (no such file): install it and try again".to_string()]);
    }
}
