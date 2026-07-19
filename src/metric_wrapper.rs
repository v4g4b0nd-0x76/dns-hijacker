use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering::Relaxed},
    },
    time::Duration,
};

use serde::Serialize;
use tokio::time::interval;

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

#[derive(Serialize)]
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
                continue
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

    async fn start_http_reporting(self: Arc<Self>) {}
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
