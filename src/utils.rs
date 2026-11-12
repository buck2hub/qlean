use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};

use dir_lock::DirLock;
use directories::ProjectDirs;
use rand::RngExt;
use tracing::{debug, trace};
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
}

/// Parse `virsh net-dhcp-leases` tabular output.
///
/// Example row:
/// ` 2026-11-12 09:35:00   52:54:00:aa:bb:cc   ipv4       192.168.221.42/24    *  -`
pub(crate) fn parse_dhcp_leases(output: &str) -> Vec<DhcpLease> {
    fn looks_like_mac(token: &str) -> bool {
        let parts = token.split(':').collect::<Vec<_>>();
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
        });
    }
    leases
}

/// Leased IPv4 address of `mac`, if the lease table has one.
///
/// A dual-stack network reports a separate IPv6 lease for the same MAC, and its
/// address is often link-local (`fe80::/10`), which is useless without a scope id.
/// Only IPv4 is returned; an IPv6-only guest keeps polling and then fails with the
/// lease list instead of connecting to an unusable address.
fn lease_address_for(leases: &[DhcpLease], mac: &str) -> Option<std::net::IpAddr> {
    leases
        .iter()
        .find(|lease| lease.mac == mac && lease.ip.is_ipv4())
        .map(|lease| lease.ip)
}

/// Resolve a MAC address to its leased address on Qlean's libvirt network.
///
/// Polling is bounded by `timeout` and never runs an unbounded retry loop. The guest
/// must be given the chance to reach DHCP, so transient "no lease yet" results are
/// expected until the address appears.
pub(crate) async fn find_lease_address(
    mac: &str,
    timeout: std::time::Duration,
) -> Result<std::net::IpAddr> {
    let mac = mac.to_ascii_lowercase();
    let deadline = tokio::time::Instant::now() + timeout;
    let mut last_seen = Vec::new();

    loop {
        let output = tokio::process::Command::new("virsh")
            .arg("-c")
            .arg(VIRSH_CONNECTION_URI)
            .arg("net-dhcp-leases")
            .arg("qlean")
            .output()
            .await
            .context("failed to execute virsh to read DHCP leases for the qlean network")?;

        if output.status.success() {
            last_seen = parse_dhcp_leases(&String::from_utf8_lossy(&output.stdout));
            if let Some(ip) = lease_address_for(&last_seen, &mac) {
                debug!("MAC {mac} leased {ip}");
                return Ok(ip);
            }
        } else {
            debug!(
                "virsh net-dhcp-leases failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }

        if tokio::time::Instant::now() >= deadline {
            bail!(
                "no DHCP lease for MAC {mac} on the `qlean` network within {}s (leases seen: {:?}).\n\
                 The guest may still be booting, or it did not bring up its virtio network device.\n\
                 Only IPv4 leases are usable: an IPv6-only lease is reported above but never dialled.",
                timeout.as_secs(),
                last_seen
                    .iter()
                    .map(|lease| format!("{}={}", lease.mac, lease.ip))
                    .collect::<Vec<_>>()
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

pub(crate) struct QleanDirs {
    pub base: PathBuf,
    pub images: PathBuf,
    pub secrets: PathBuf,
    pub runs: PathBuf,
}

impl QleanDirs {
    pub(crate) fn new() -> Result<Self> {
        let project_dir = ProjectDirs::from("", "", "qlean").expect("Couldn't get project dir");

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

pub(crate) fn create_dir(purpose: &str, path: &Path) -> Result<()> {
    if !path.exists() {
        debug!("{purpose} dir {path:?} doesn't exist yet, creating");
        std::fs::create_dir_all(path).expect("Failed to create directory");
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

/// Ensure the guest-independent host prerequisites (CLI tools and the Qlean network).
pub(crate) async fn ensure_host_prerequisites() -> Result<()> {
    check_command_available("qemu-system-x86_64").await?;
    check_command_available("qemu-img").await?;
    check_command_available("xorriso").await?;
    check_command_available("virsh").await?;
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

async fn check_command_available(cmd: &str) -> Result<()> {
    let _ = tokio::process::Command::new(cmd)
        .arg("--version")
        .output()
        .await
        .with_context(|| format!("could not find {}", cmd))?;
    Ok(())
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
    let output = tokio::process::Command::new("virsh")
        .arg("-c")
        .arg(VIRSH_CONNECTION_URI)
        .arg("net-list")
        .arg("--name")
        .arg("--all")
        .output()
        .await
        .context("failed to execute virsh to check qlean network")?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let all_networks = stdout.lines().map(str::to_owned).collect::<HashSet<_>>();
    let net_exists = all_networks.contains("qlean");

    let output = tokio::process::Command::new("virsh")
        .arg("-c")
        .arg(VIRSH_CONNECTION_URI)
        .arg("net-list")
        .arg("--name")
        .output()
        .await
        .context("failed to execute virsh to check qlean network")?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let active_networks = stdout.lines().map(str::to_owned).collect::<HashSet<_>>();
    let net_active = active_networks.contains("qlean");

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

        let status = tokio::process::Command::new("virsh")
            .arg("-c")
            .arg(VIRSH_CONNECTION_URI)
            .arg("net-define")
            .arg(&xml_path)
            .status()
            .await
            .context("failed to execute virsh to define qlean network")?;
        if !status.success() {
            bail!("failed to define qlean network");
        }
    }

    if !net_exists || !net_active {
        debug!("Starting qlean network");
        let status = tokio::process::Command::new("virsh")
            .arg("-c")
            .arg(VIRSH_CONNECTION_URI)
            .arg("net-autostart")
            .arg("qlean")
            .status()
            .await
            .context("failed to execute virsh to autostart qlean network")?;
        if !status.success() {
            bail!("failed to autostart qlean network");
        }

        let status = tokio::process::Command::new("virsh")
            .arg("-c")
            .arg(VIRSH_CONNECTION_URI)
            .arg("net-start")
            .arg("qlean")
            .status()
            .await
            .context("failed to execute virsh to start qlean network")?;
        if !status.success() {
            bail!("failed to start qlean network");
        }
    }
    Ok(())
}

pub(crate) fn gen_random_mac() -> String {
    let mut rng = rand::rng();
    let bytes: [u8; 6] = [0x52, 0x54, 0x00, rng.random(), rng.random(), rng.random()];
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

pub(crate) fn qlean_user_agent() -> &'static str {
    "qlean/0.3.0"
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEASES_HEADER: &str = "\
 Expiry Time           MAC address         Protocol   IP address           Hostname   Client ID or DUID
---------------------------------------------------------------------------------------------------------
";

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
    fn test_parse_dhcp_leases_handles_ipv6_rows() {
        let output = format!(
            "{LEASES_HEADER} 2026-11-12 09:35:00   52:54:00:aa:bb:cc   ipv6       fd00::42/64    *  -\n"
        );
        let leases = parse_dhcp_leases(&output);
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].ip.to_string(), "fd00::42");
    }
}
