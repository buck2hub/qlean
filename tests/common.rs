use std::sync::Once;
use tracing_subscriber::{EnvFilter, fmt::time::LocalTime};

pub fn tracing_subscriber_init() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .with_timer(LocalTime::rfc_3339())
            .init();
    });
}
