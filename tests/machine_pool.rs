use anyhow::Result;
use qlean::{Distro, MachineConfig, create_image, with_pool};

#[path = "support/logging.rs"]
mod logging;
use logging::tracing_subscriber_init;

#[tokio::test]
async fn test_ping() -> Result<()> {
    tracing_subscriber_init();

    with_pool(|pool| {
        Box::pin(async {
            let image = create_image(Distro::Debian, "debian-13-generic-amd64").await?;
            let config = MachineConfig::default();

            pool.add("alice".to_string(), &image, &config).await?;
            pool.add("bob".to_string(), &image, &config).await?;
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
async fn test_concurrency() -> Result<()> {
    tracing_subscriber_init();

    with_pool(|pool| {
        Box::pin(async {
            let image = create_image(Distro::Debian, "debian-13-generic-amd64").await?;
            let config = MachineConfig::default();

            pool.add("vm1".to_string(), &image, &config).await?;
            pool.add("vm2".to_string(), &image, &config).await?;
            pool.add("vm3".to_string(), &image, &config).await?;
            pool.add("vm4".to_string(), &image, &config).await?;

            pool.init_all().await?;
            pool.shutdown_all().await?;
            pool.spawn_all().await?;

            Ok(())
        })
    })
    .await?;

    Ok(())
}
