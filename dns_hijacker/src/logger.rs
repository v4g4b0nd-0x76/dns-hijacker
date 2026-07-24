use std::{
    fs::{OpenOptions, create_dir_all},
    sync::Mutex,
};

use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt};

/// Initialize stdout + append-only file logging at INFO.
pub fn init_logger() {
    let _ = create_dir_all("logs");
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("logs/dns_hijacker.log")
        .expect("failed to open log file");

    tracing_subscriber::registry()
        .with(LevelFilter::INFO)
        .with(fmt::layer().with_ansi(false))
        .with(fmt::layer().with_writer(Mutex::new(file)).with_ansi(false))
        .init();
}
