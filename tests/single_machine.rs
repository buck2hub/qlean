#[tokio::test]
async fn hello() -> anyhow::Result<()> {
    use qlean::{Distro, MachineConfig};
    use tracing_subscriber::{filter::EnvFilter, fmt::time::LocalTime};

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_timer(LocalTime::rfc_3339())
        .init();

    let image = qlean::create_image(Distro::Debian, "debian-13-generic-amd64").await?;
    let config = MachineConfig::default();

    qlean::with_machine(&image, &config, |vm| {
        Box::pin(async {
            // Here you can interact with the VM
            let result = vm.exec("whoami").await?;
            assert!(result.status.success());
            assert_eq!(str::from_utf8(&result.stdout)?.trim(), "root");

            Ok(())
        })
    })
    .await?;

    Ok(())
}
