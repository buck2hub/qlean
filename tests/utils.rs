use std::sync::Once;

use tracing_indicatif::IndicatifLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt::time::LocalTime};

/// Initialize a global tracing subscriber for integration tests.
///
/// Multiple integration test crates may attempt to install a global subscriber.
/// We use `try_init()` to avoid panics if one is already set.
pub fn tracing_subscriber_init() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let env_filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,qlean=info"));
        let indicatif_layer = IndicatifLayer::new();
        tracing_subscriber::registry()
            .with(env_filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .with_timer(LocalTime::rfc_3339())
                    .with_writer(indicatif_layer.get_stderr_writer()),
            )
            .with(indicatif_layer)
            .try_init()
            .ok();
    });
}
