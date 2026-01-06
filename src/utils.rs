use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use dir_lock::DirLock;
use directories::ProjectDirs;
use tracing::{debug, trace};
use walkdir::WalkDir;

pub static HEX_ALPHABET: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];

pub struct QleanDirs {
    pub images: PathBuf,
    pub secrets: PathBuf,
    pub runs: PathBuf,
}

impl QleanDirs {
    pub fn new() -> Result<Self> {
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
            images,
            secrets,
            runs,
        })
    }
}

pub fn create_dir(purpose: &str, path: &Path) -> Result<()> {
    if !path.exists() {
        debug!("{purpose} dir {path:?} doesn't exist yet, creating");
        std::fs::create_dir_all(path).expect("Failed to create directory");
    }
    Ok(())
}

pub fn get_free_cid(runs_dir: &Path, run_dir: &Path) -> Result<u32> {
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

pub async fn ensure_prerequisites() -> Result<()> {
    check_command_available("qemu-system-x86_64").await?;
    check_command_available("qemu-img").await?;
    check_command_available("sha256sum").await?;
    check_command_available("sha512sum").await?;
    check_command_available("xorriso").await?;
    check_command_available("guestfish").await?;
    check_command_available("virt-copy-out").await?;
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
