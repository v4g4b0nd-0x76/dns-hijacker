use arc_swap::ArcSwap;
use clap::{Parser, Subcommand};
use dns_hijacker::{
    Error, ResolverPicker, bind_udp_socket, build_http_client,
    conf::watch_conf_and_reload,
    constants::{
        BACKLOG_CAPACITY, LOCAL_DNS, MAX_BACKLOG_AGE_MS, PAYLOAD_BUF_SIZE, RECV_BATCH_MAX,
        RESOLVE_SEMAPHORE,
    },
    gen_relay_key, handle_query,
    handler::{DomainTrie, HandleQueryParams},
    helpers::clear_screen,
    init_logger, load_conf,
    metric_wrapper::MetricWrapper,
    netguard::run_network_guard,
    new_cache,
    relay::{RelayPicker, resolve_domain_via_relay},
    resolver::Resolver,
    run_resolver_finder,
};
use std::{
    io,
    path::PathBuf,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering::Relaxed},
    },
    time::Duration,
};
use tokio::{net::UdpSocket, sync::Semaphore};
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(
    name = "dns-hijacker",
    version,
    about = "Block, Redirect or Resolve your DNS query as you want"
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
    /// Run the DNS server (default if no subcommand given)
    Run,

    /// Validate the config file and exit
    CheckConf,

    /// Print the current blocklist / redirect list and exit
    ListRules,

    Resolvers,

    Resolve {
        #[arg(required = true)]
        domain: String,
        #[arg(long)]
        relay: bool,
        #[arg(required = false)]
        resolver: Option<String>,
    },

    GenRelayKey,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Error> {
    init_logger();
    let cli = Cli::parse();

    match cli.command.unwrap_or(Commands::Run) {
        Commands::Run => run_server(&cli.conf).await,
        Commands::CheckConf => check_conf(&cli.conf),
        Commands::ListRules => list_rules(&cli.conf),
        Commands::Resolvers => list_resolvers(&cli.conf).await,
        Commands::GenRelayKey => gen_relay_key(&cli.conf),
        Commands::Resolve {
            domain,
            resolver,
            relay,
        } => resolve(&cli.conf, &domain, resolver, relay).await,
    }
}

async fn run_server(conf_path: &PathBuf) -> Result<(), Error> {
    let conf = Arc::new(RwLock::new(load_conf(conf_path)?));
    let cache = Arc::new(new_cache());
    let metric_conf = conf.read().unwrap().metric_conf.clone();
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

    let hotreload_conf = {
        let conf_read = conf.read().unwrap();
        conf_read.hotreload_conf.clone()
    };

    let rule_trie: Arc<ArcSwap<DomainTrie>> = {
        let conf_read = conf.read().unwrap();
        Arc::new(ArcSwap::from_pointee(DomainTrie::build(
            &conf_read.drop_list,
            &conf_read.redirect_list,
        )))
    };
    tokio::spawn(watch_conf_and_reload(
        conf_path.clone(),
        Duration::from_millis(hotreload_conf.poll_interval_ms),
        Arc::clone(&conf),
        Arc::clone(&rule_trie),
        Arc::clone(&cache),
    ));
    let is_vpn_active = Arc::new(AtomicBool::new(false));
    tokio::spawn(run_network_guard(Arc::clone(&is_vpn_active)));
    let http = build_http_client()?;
    let (initial_resolvers, resolver_searching, searching_enabled, relay_conf) = {
        let conf_read = conf.read().unwrap();
        (
            conf_read.resolvers.clone(),
            conf_read.resolver_searching.clone(),
            conf_read.resolver_searching.enable
                && !conf_read.resolver_searching.resolver_source.is_empty(),
            conf_read.relay_conf.clone(),
        )
    };

    let receiver_socket = Arc::new(
        UdpSocket::bind("0.0.0.0:0")
            .await
            .expect("failed to bind receiver socket"),
    );
    let resolver_picker =
        ResolverPicker::new(initial_resolvers, http.clone(), &receiver_socket).await?;
    let relay_pciker = if relay_conf.enable {
        Some(Arc::new(
            RelayPicker::new(&relay_conf, &resolver_picker, &http).await?,
        ))
    } else {
        None
    };
    if searching_enabled {
        let healthy_resolvers = resolver_picker.healthy_resolvers();
        tokio::spawn(async move {
            let is_searching: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
            if let Err(err) =
                run_resolver_finder(resolver_searching, healthy_resolvers, is_searching).await
            {
                error!("error in resolver finder: {}", err);
            }
        });
    }

    let server_socket = Arc::new(bind_udp_socket(LOCAL_DNS)?);
    let resolve_sem = Arc::new(Semaphore::new(RESOLVE_SEMAPHORE));

    let (backlog_tx, mut backlog_rx) =
        tokio::sync::mpsc::channel::<(Vec<u8>, std::net::SocketAddr, tokio::time::Instant)>(
            BACKLOG_CAPACITY,
        );

    {
        let resolve_sem = Arc::clone(&resolve_sem);
        let rule_trie = Arc::clone(&rule_trie);
        let http = http.clone();
        let resolver_picker = resolver_picker.clone();
        let server_socket = Arc::clone(&server_socket);
        let cache = Arc::clone(&cache);
        let relay_picker = relay_pciker.clone();
        let metric_wrapper = metric_wrapper.clone();
        let max_age = Duration::from_millis(MAX_BACKLOG_AGE_MS);
        let is_vpn_active = Arc::clone(&is_vpn_active);

        tokio::spawn(async move {
            loop {
                let (payload, src_addr) = loop {
                    match backlog_rx.recv().await {
                        Some((payload, src_addr, enqueued_at)) => {
                            if enqueued_at.elapsed() > max_age {
                                warn!(
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

                let rule_trie = rule_trie.load_full();
                let http = http.clone();
                let resolver_picker = resolver_picker.clone();
                let server_socket = Arc::clone(&server_socket);
                let cache = Arc::clone(&cache);
                let relay_picker = relay_picker.clone();
                let metric_wrapper = metric_wrapper.clone();
                let is_vpn_active = is_vpn_active.clone();

                tokio::spawn(async move {
                    let _permit = permit;
                    let params = HandleQueryParams {
                        payload: &payload,
                        src_addr,
                        rule_trie: &rule_trie,
                        resolver_picker: &resolver_picker,
                        server_socket: &server_socket,
                        http: &http,
                        cache: &cache,
                        relay_picker: relay_picker.as_deref(),
                        metric_wrapper: metric_wrapper.as_ref(),
                        is_vpn_active: &is_vpn_active,
                    };
                    handle_query(&params).await;
                });
            }
        });
    }

    info!("dns server listening at {}", LOCAL_DNS);
    let mut buf = [0u8; PAYLOAD_BUF_SIZE];
    loop {
        let (len, src_addr) = match server_socket.recv_from(&mut buf).await {
            Ok(res) => res,
            Err(err) => {
                error!("failed to receive payload: {}", err);
                continue;
            }
        };
        let mut batch = Vec::with_capacity(RECV_BATCH_MAX);
        batch.push((buf[..len].to_vec(), src_addr));
        while batch.len() < RECV_BATCH_MAX {
            match server_socket.try_recv_from(&mut buf) {
                Ok((n, addr)) => batch.push((buf[..n].to_vec(), addr)),
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => break,
                Err(err) => {
                    error!("failed to drain payload: {}", err);
                    break;
                }
            }
        }
        if let Some(metric_wrapper) = metric_wrapper.as_ref() {
            metric_wrapper
                .total_req
                .fetch_add(batch.len() as u64, Relaxed);
        }
        for (payload, src_addr) in batch {
            let Ok(permit) = resolve_sem.clone().try_acquire_owned() else {
                match backlog_tx.try_send((payload, src_addr, tokio::time::Instant::now())) {
                    Ok(_) => {
                        if let Some(m) = metric_wrapper.as_ref() {
                            m.total_req.fetch_add(0, Relaxed);
                        }
                    }
                    Err(_) => {
                        warn!("semaphore and backlog both full, dropping query");
                    }
                }
                continue;
            };
            let rule_trie = rule_trie.load_full();
            let http = http.clone();
            let resolver_picker = resolver_picker.clone();
            let server_socket = Arc::clone(&server_socket);
            let cache = Arc::clone(&cache);
            let relay_picker = relay_pciker.clone();
            let metric_wrapper = metric_wrapper.clone();
            let is_vpn_active = is_vpn_active.clone();

            tokio::spawn(async move {
                let _permit = permit;
                let params = HandleQueryParams {
                    payload: &payload,
                    src_addr,
                    rule_trie: &rule_trie,
                    resolver_picker: &resolver_picker,
                    server_socket: &server_socket,
                    http: &http,
                    cache: &cache,
                    relay_picker: relay_picker.as_deref(),
                    metric_wrapper: metric_wrapper.as_ref(),
                    is_vpn_active: &is_vpn_active,
                };
                handle_query(&params).await;
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

async fn list_resolvers(conf_path: &PathBuf) -> Result<(), Error> {
    let conf = load_conf(conf_path)?;
    let http = build_http_client()?;
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    let resolver_picker = ResolverPicker::new(conf.resolvers, http.clone(), &socket).await?;
    let healthy = resolver_picker.healthy_resolvers();
    let top_resolvers: Vec<Resolver> = {
        let guard = healthy.read().unwrap();
        let n = 10.min(guard.len());
        guard[..n].to_vec()
    };
    clear_screen();
    println!("{:<4}{:<40}{:>10}", "#", "Address", "Latency (ms)");
    println!("{}", "-".repeat(54));
    for (i, (addr, delay_ms)) in top_resolvers.iter().enumerate() {
        println!("{:<4}{:<40}{:>10}\n", i + 1, addr, delay_ms.as_millis());
    }

    Ok(())
}

async fn resolve(
    conf_path: &PathBuf,
    domain: &str,
    resolver: Option<String>,
    relay: bool,
) -> Result<(), Error> {
    let conf = load_conf(conf_path)?;
    let http = build_http_client()?;

    let receiver_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    let resolver_picker =
        ResolverPicker::new(conf.resolvers, http.clone(), &receiver_socket).await?;
    if relay {
        if conf.relay_conf.relay_instances.is_empty() {
            return Err(Error::Other(
                "please define relay instances for using relay as resolver".to_string(),
            ));
        }

        let relay_pciker = RelayPicker::new(&conf.relay_conf, &resolver_picker, &http).await?;

        let relay_client = relay_pciker.pick();
        let relay_resp = resolve_domain_via_relay(
            relay_client.client(),
            relay_client.url(),
            relay_client.key(),
            domain,
        )
        .await?;

        if relay_resp.is_empty() {
            println!(";; no A records found for {domain}");
        } else {
            for ip in relay_resp {
                println!("\n{domain}.\tIN\tA\t{ip}");
            }
        }
    } else {
        let resolved = resolver_picker.resolve(domain, resolver, &http).await?;
        if resolved.is_empty() {
            println!(";; no A records found for {domain}");
        } else {
            for ip in resolved {
                println!("\n{domain}.\tIN\tA\t{ip}");
            }
        }
    }

    Ok(())
}
