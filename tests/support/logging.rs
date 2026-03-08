use std::sync::Once;

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
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_timer(LocalTime::rfc_3339())
            .try_init()
            .ok();
    });
}
