use anyhow::Result;
use qlean::{Distro, Image, ImageConfig, MachineConfig, with_pool};
use serial_test::serial;

mod utils;
use utils::tracing_subscriber_init;

#[tokio::test]
#[serial]
async fn test_ping() -> Result<()> {
    tracing_subscriber_init();

    with_pool(|pool| {
        Box::pin(async {
            let image = Image::new(ImageConfig::default().with_distro(Distro::Debian)).await?;
            let config = MachineConfig::default();

            pool.add("alice", &image, &config).await?;
            pool.add("bob", &image, &config).await?;
            pool.init_all().await?;

            let mut alice = pool.get("alice").await.expect("Alice machine not found");
            let mut bob = pool.get("bob").await.expect("Bob machine not found");

            let alice_ip = alice.get_ip().await?;
            let result = bob.exec(format!("ping -c 4 {}", alice_ip)).await?;
            assert!(result.status.success());
            let bob_ip = bob.get_ip().await?;
            let result = alice.exec(format!("ping -c 4 {}", bob_ip)).await?;
            assert!(result.status.success());

            Ok(())
        })
    })
    .await?;

    Ok(())
}

#[tokio::test]
#[serial]
async fn test_concurrency() -> Result<()> {
    tracing_subscriber_init();

    with_pool(|pool| {
        Box::pin(async {
            let image = Image::new(ImageConfig::default().with_distro(Distro::Debian)).await?;
            let config = MachineConfig::default();

            pool.add("vm1", &image, &config).await?;
            pool.add("vm2", &image, &config).await?;
            pool.add("vm3", &image, &config).await?;
            pool.add("vm4", &image, &config).await?;

            pool.init_all().await?;
            pool.shutdown_all().await?;
            pool.spawn_all().await?;

            Ok(())
        })
    })
    .await?;

    Ok(())
}
