use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering::Relaxed},
    },
    time::Duration,
};

use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    time::interval,
};

use crate::conf::{MetricConf, MetricReportType};

#[derive(Default)]
pub struct MetricWrapper {
    pub total_req: AtomicU64,
    pub resolved_count: AtomicU64,
    pub failed_count: AtomicU64,
    pub timeout_count: AtomicU64,
    pub redirect_count: AtomicU64,
    pub drop_count: AtomicU64,
    pub cached_count: AtomicU64,
    pub relay_resolved_count: AtomicU64,
}

pub struct ResolverMetricWrapper {
    pub resolver: String,
    pub resolved_count: AtomicU64,
    pub failed_count: AtomicU64,
}

impl ResolverMetricWrapper {
    pub fn new(resolver: &str) -> Self {
        Self {
            resolver: resolver.to_string(),
            resolved_count: AtomicU64::new(0),
            failed_count: AtomicU64::new(0),
        }
    }
}

#[derive(serde::Serialize)]
struct MetricReport {
    pub total_req: u64,
    pub resolved_count: u64,
    pub failed_count: u64,
    pub timeout_count: u64,
    pub redirect_count: u64,
    pub drop_count: u64,
    pub cached_count: u64,
    pub relay_resolved_count: u64,
}

impl MetricWrapper {
    pub fn new() -> Self {
        Self::default()
    }
    pub async fn start_reporting(self: Arc<Self>, conf: &MetricConf) {
        match conf.report_type {
            MetricReportType::Log => self.start_log_reporting(conf.report_interval).await,
            MetricReportType::Http => self.start_http_reporting().await,
        }
    }
    async fn start_log_reporting(self: Arc<Self>, report_interval: u64) {
        let mut tk = interval(Duration::from_secs(report_interval));
        let mut last_total_count = 0;
        loop {
            tk.tick().await;
            tracing::info!("Reporting metrics");
            let report = self.prepare_report();
            if report.total_req == last_total_count {
                continue;
            }
            last_total_count = report.total_req;
            tracing::info!(
                "\nMetrics Report:\nTotal DNS Query: {}\nTotal Resolved Count: {}\nTotal Failed Count: {}\nTotal Timeout Count: {}\nTotal Redirected Count: {}\nTotal Droped Count: {}\nTotal Cached Count: {}\nTotal Relay Resolved Count: {}\n",
                report.total_req,
                report.resolved_count,
                report.failed_count,
                report.timeout_count,
                report.redirect_count,
                report.drop_count,
                report.cached_count,
                report.relay_resolved_count
            );
        }
    }

    async fn start_http_reporting(self: Arc<Self>) {
        let listener = match TcpListener::bind("127.0.0.1:5053").await {
            Ok(l) => l,
            Err(err) => {
                tracing::error!("Failed to start http router: {}", err);
                return;
            }
        };
        loop {
            let (stream, _addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(err) => {
                    tracing::error!("failed to accept http connection: {}", err);
                    continue;
                }
            };
            let this = Arc::clone(&self);
            tokio::spawn(async move {
                this.handle_metrics_connection(stream).await;
            });
        }
    }

    async fn handle_metrics_connection(&self, stream: TcpStream) {
        let mut reader = BufReader::new(stream);
        let mut request_line = String::new();
        if let Err(err) = reader.read_line(&mut request_line).await {
            tracing::warn!("failed to read http request: {}", err);
            return;
        }
        if request_line.is_empty() {
            return; // connection closed before sending anything
        }

        // request_line looks like: "GET /metrics HTTP/1.1\r\n"
        let path = request_line.split_whitespace().nth(1).unwrap_or("");

        let (status_line, content_type, body) = match path {
            "/metrics" => {
                let report = self.prepare_report();
                match serde_json::to_string(&report) {
                    Ok(json) => ("HTTP/1.1 200 OK", "application/json", json),
                    Err(err) => {
                        tracing::error!("failed to serialize metrics report: {}", err);
                        (
                            "HTTP/1.1 500 INTERNAL SERVER ERROR",
                            "text/plain",
                            "failed to serialize metrics".to_string(),
                        )
                    }
                }
            }
            "/health" => ("HTTP/1.1 200 Healthy", "text/plain", "ok".to_string()),
            _ => (
                "HTTP/1.1 404 NOT FOUND",
                "text/plain",
                "not found".to_string(),
            ),
        };

        let response = format!(
            "{status_line}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );

        let stream = reader.into_inner();
        let mut stream = stream;
        if let Err(err) = stream.write_all(response.as_bytes()).await {
            tracing::warn!("failed to write http response: {}", err);
        }
    }
    fn prepare_report(&self) -> MetricReport {
        MetricReport {
            total_req: self.total_req.load(Relaxed), // in here we can aquire as well but for sake of performance and non critiality of this  report we dont do it
            resolved_count: self.resolved_count.load(Relaxed),
            failed_count: self.failed_count.load(Relaxed),
            timeout_count: self.timeout_count.load(Relaxed),
            redirect_count: self.redirect_count.load(Relaxed),
            drop_count: self.drop_count.load(Relaxed),
            cached_count: self.cached_count.load(Relaxed),
            relay_resolved_count: self.relay_resolved_count.load(Relaxed),
        }
    }
}
