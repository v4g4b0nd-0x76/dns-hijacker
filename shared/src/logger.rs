use file_rotate::{ContentLimit, FileRotate, compression::Compression, suffix::AppendCount};
use std::fs::create_dir_all;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

pub fn init_logger() -> WorkerGuard {
    create_dir_all("logs").expect("failed to create log directory");

    let file_appender = FileRotate::new(
        "logs/app.log",
        AppendCount::new(10),
        ContentLimit::Bytes(1_000_000_000),
        Compression::None,
        #[cfg(unix)]
        None,
    );

    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(non_blocking)
                .with_ansi(false),
        )
        .init();

    guard
}
