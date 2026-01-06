use std::future::Future;
use std::pin::Pin;

use anyhow::{Error, Result};

use crate::utils::ensure_prerequisites;

mod image;
mod machine;
mod qemu;
mod ssh;
mod utils;

pub use image::Distro;
pub use image::Image;
pub use image::create_image;
pub use machine::{Machine, MachineConfig};

pub async fn with_machine<'a, F, R>(image: &'a Image, config: &'a MachineConfig, f: F) -> Result<R>
where
    F: for<'b> FnOnce(&'b mut Machine) -> Pin<Box<dyn Future<Output = Result<R, Error>> + 'b>>,
{
    #[cfg(not(target_os = "linux"))]
    {
        return Err(anyhow!("qlean currently only supports Linux hosts."));
    }

    ensure_prerequisites().await?;

    let mut machine = Machine::new(image, config).await?;
    machine.init().await?;
    let result = f(&mut machine).await;
    machine.shutdown().await?;

    result
}
