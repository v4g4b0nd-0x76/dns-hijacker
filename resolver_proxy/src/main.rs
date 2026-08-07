use std::{
    path::PathBuf,
    sync::{Arc, RwLock, atomic::AtomicBool},
    time::Duration,
};

use arc_swap::ArcSwap;
use clap::{Parser, Subcommand};
use resolver_proxy::{
    conf::{load_conf, watch_conf_and_reload},
    handler::{HandleQueryParams, TargetPicker, handle_query, resolve_targets},
};
use shared::{
    Error, bind_udp_socket,
    cache::new_cache,
    constants::{
        BACKLOG_CAPACITY, MAX_BACKLOG_AGE_MS, PAYLOAD_BUF_SIZE, RECV_BATCH_MAX, RESOLVE_SEMAPHORE,
    },
    domain_trie::DomainTrie,
    gen_relay_key,
    logger::init_logger,
    metric_wrapper::MetricWrapper,
    netguard::run_network_guard,
    obfs::ObfsKey,
};
use tokio::sync::Semaphore;

#[derive(Parser)]
#[command(
    name = "resolver-proxy",
    version,
    about = "Connect to dns_relay server"
)]
struct Cli {
    /// Path to config file
    #[arg(short, long, default_value = "conf.toml", global = true)]
    conf: PathBuf,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the Proxy server
    Run,

    /// Validate the config file and exit
    CheckConf,

    /// Print the current blocklist / redirect list and exit
    ListRules,

    GenRelayKey,
    GenObfsKey,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Error> {
    let _ = init_logger();
    let cli = Cli::parse();

    match cli.command.unwrap_or(Commands::Run) {
        Commands::Run => run_server(&cli.conf).await,
        Commands::CheckConf => check_conf(&cli.conf),
        Commands::ListRules => list_rules(&cli.conf),
        Commands::GenRelayKey => gen_relay_key(&cli.conf),
        Commands::GenObfsKey => gen_obfs_key(),
    }
}

async fn run_server(conf_path: &PathBuf) -> Result<(), Error> {
    let conf = Arc::new(RwLock::new(load_conf(conf_path)?));

    let (hotreload_conf, metric_conf, vpn_reassertion, targets_conf, listen_addr) = {
        let conf_read = conf.read().unwrap();
        (
            conf_read.hotreload_conf.clone(),
            conf_read.metric_conf.clone(),
            conf_read.vpn_reassertion,
            conf_read.targets.clone(),
            conf_read.dns_target.clone(),
        )
    };

    let rule_trie: Arc<ArcSwap<DomainTrie>> = {
        let conf_read = conf.read().unwrap();
        Arc::new(ArcSwap::from_pointee(DomainTrie::build(
            &conf_read.drop_list,
            &conf_read.redirect_list,
        )))
    };
    if hotreload_conf.enable {
        tokio::spawn(watch_conf_and_reload(
            conf_path.clone(),
            Duration::from_millis(hotreload_conf.poll_interval_ms),
            Arc::clone(&conf),
            Arc::clone(&rule_trie),
        ));
    }
    if vpn_reassertion {
        let listen_addr_clone = listen_addr
            .split(':')
            .next()
            .unwrap_or(&listen_addr)
            .to_string();

        tokio::spawn(run_network_guard(
            Arc::new(AtomicBool::new(true)),
            listen_addr_clone,
        )); // as we dont resolve in this app there is no need to track vpn status
    };

    let metric_wrapper = if metric_conf.enable {
        let metric_wrapper = Arc::new(MetricWrapper::new());
        let metric_report_wrapper = Arc::clone(&metric_wrapper);
        tokio::spawn(async move {
            metric_report_wrapper.start_reporting(&metric_conf).await;
        });
        Some(metric_wrapper)
    } else {
        None
    };
    let target_picker = Arc::new(TargetPicker::new(
        resolve_targets(&targets_conf)?,
        targets_conf.strategy.clone(),
    )?);

    let server_socket = Arc::new(bind_udp_socket(&listen_addr)?);
    let resolve_sem = Arc::new(Semaphore::new(RESOLVE_SEMAPHORE));
    let cache = Arc::new(new_cache());

    let (backlog_tx, mut backlog_rx) =
        tokio::sync::mpsc::channel::<(Vec<u8>, std::net::SocketAddr, tokio::time::Instant)>(
            BACKLOG_CAPACITY,
        );
    let max_age = Duration::from_millis(MAX_BACKLOG_AGE_MS);

    {
        let resolve_sem = Arc::clone(&resolve_sem);
        let rule_trie = Arc::clone(&rule_trie);
        let metric_wrapper = metric_wrapper.clone();
        let cache = Arc::clone(&cache);
        let server_socket = Arc::clone(&server_socket);
        let target_picker = Arc::clone(&target_picker);

        tokio::spawn(async move {
            loop {
                let (payload, src_addr) = loop {
                    match backlog_rx.recv().await {
                        Some((payload, src_addr, enqueued_at)) => {
                            if enqueued_at.elapsed() > max_age {
                                tracing::warn!(
                                    "dropping stale backlogged query ({:?} old)",
                                    enqueued_at.elapsed()
                                );
                                continue;
                            }
                            break (payload, src_addr);
                        }
                        None => return,
                    }
                };

                let Ok(permit) = resolve_sem.clone().acquire_owned().await else {
                    return;
                };
                let metric_wrapper = metric_wrapper.clone();
                let rule_trie = rule_trie.load_full();
                let cache = Arc::clone(&cache);
                let server_socket = Arc::clone(&server_socket);

                let target_picker = Arc::clone(&target_picker);
                tokio::spawn(async move {
                    let _permit = permit;
                    let params = HandleQueryParams {
                        payload: &payload,
                        src_addr,
                        rule_trie: &rule_trie,
                        server_socket: &server_socket,
                        cache: &cache,
                        metric_wrapper: metric_wrapper.as_ref(),
                        target_picker: &target_picker,
                    };
                    handle_query(&params).await
                    // handle query
                });
            }
        });
    }
    tracing::info!("dns server listening at {}", &listen_addr);
    let mut buf = [0u8; PAYLOAD_BUF_SIZE];
    loop {
        let (len, src_addr) = match server_socket.recv_from(&mut buf).await {
            Ok(res) => res,
            Err(err) => {
                tracing::error!("failed to receive payload: {}", err);
                continue;
            }
        };
        let mut batch = Vec::with_capacity(RECV_BATCH_MAX);
        batch.push((buf[..len].to_vec(), src_addr));
        while batch.len() < RECV_BATCH_MAX {
            match server_socket.try_recv_from(&mut buf) {
                Ok((n, addr)) => batch.push((buf[..n].to_vec(), addr)),
                Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(err) => {
                    tracing::error!("failed to drain payload: {}", err);
                    break;
                }
            }
        }
        if let Some(metric_wrapper) = metric_wrapper.as_ref() {
            metric_wrapper
                .total_req
                .fetch_add(batch.len() as u64, std::sync::atomic::Ordering::Relaxed);
        }

        for (payload, src_addr) in batch {
            let Ok(permit) = resolve_sem.clone().try_acquire_owned() else {
                match backlog_tx.try_send((payload, src_addr, tokio::time::Instant::now())) {
                    Ok(_) => {}
                    Err(_) => {
                        tracing::warn!("semaphore and backlog both full, dropping query");
                    }
                }
                continue;
            };
            let metric_wrapper = metric_wrapper.clone();
            let rule_trie = rule_trie.load_full();
            let cache = Arc::clone(&cache);
            let server_socket = Arc::clone(&server_socket);

            let target_picker = Arc::clone(&target_picker);
            tokio::spawn(async move {
                let _permit = permit;
                let params = HandleQueryParams {
                    payload: &payload,
                    src_addr,
                    rule_trie: &rule_trie,
                    server_socket: &server_socket,
                    cache: &cache,
                    metric_wrapper: metric_wrapper.as_ref(),
                    target_picker: &target_picker,
                };
                handle_query(&params).await
                // handle query
            });
        }
    }
}

fn check_conf(conf_path: &PathBuf) -> Result<(), Error> {
    match load_conf(conf_path) {
        Ok(conf) => {
            println!(
                "conf OK: {} redirect rules, {} drop rules",
                conf.redirect_list.len(),
                conf.drop_list.len()
            );
            Ok(())
        }
        Err(e) => {
            eprintln!("conf error: {e}");
            Err(e)
        }
    }
}

fn list_rules(conf_path: &PathBuf) -> Result<(), Error> {
    let conf = load_conf(conf_path)?;
    for domain in &conf.drop_list {
        println!("DROP    {domain}");
    }
    for (from, to) in &conf.redirect_list {
        println!("REDIRECT {from} -> {to}");
    }
    Ok(())
}

fn gen_obfs_key() -> Result<(), Error> {
    let key = ObfsKey::generate_base64();
    println!("{key}");
    Ok(())
}
