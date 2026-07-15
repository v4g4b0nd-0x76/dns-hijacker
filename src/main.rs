use arc_swap::ArcSwap;
use clap::{Parser, Subcommand};
use dns_hijacker::{
    Error, ResolverPicker, bind_udp_socket, build_http_client, cache::new_domain_cache, conf::watch_conf_and_reload, constants::{LOCAL_DNS, PAYLOAD_BUF_SIZE, RECV_BATCH_MAX, RESOLVE_SEMAPHORE}, gen_relay_key, handle_query, helpers::clear_screen, init_logger, load_conf, new_cache, relay::load_key_from_str, resolver::Resolver, run_resolver_finder
};
use std::{
    io,
    path::PathBuf,
    sync::{Arc, RwLock, atomic::AtomicBool},
    time::Duration,
};
use tokio::sync::Semaphore;
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

        #[arg(required = false)]
        resolver: Option<String>,
    },

    GenRelayKey,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    init_logger();
    let cli = Cli::parse();

    match cli.command.unwrap_or(Commands::Run) {
        Commands::Run => run_server(&cli.conf).await,
        Commands::CheckConf => check_conf(&cli.conf),
        Commands::ListRules => list_rules(&cli.conf),
        Commands::Resolvers => list_resolvers(&cli.conf).await,
        Commands::GenRelayKey => gen_relay_key(&cli.conf),
        Commands::Resolve { domain, resolver } => resolve(&cli.conf, &domain, resolver).await,
    }
}

async fn run_server(conf_path: &PathBuf) -> Result<(), Error> {
    let conf = Arc::new(RwLock::new(load_conf(conf_path)?));
    let hotreload_conf = {
        let conf_read = conf.read().unwrap();
        conf_read.hotreload_conf.clone()
    };
    let redirect_list: Arc<ArcSwap<Vec<(String, String)>>> = {
        let conf_read = conf.read().unwrap();
        Arc::new(ArcSwap::from_pointee(conf_read.redirect_list.clone()))
    };
    let drop_list: Arc<ArcSwap<Vec<String>>> = {
        let conf_read = conf.read().unwrap();
        Arc::new(ArcSwap::from_pointee(conf_read.drop_list.clone()))
    };
    tokio::spawn(watch_conf_and_reload(
        conf_path.clone(),
        Duration::from_millis(hotreload_conf.poll_interval_ms),
        Arc::clone(&conf),
        Arc::clone(&redirect_list),
        Arc::clone(&drop_list),
    ));
    let http = build_http_client()?;
    let (initial_resolvers, resolver_searching, searching_enabled, mut relay_conf) = {
        let conf_read = conf.read().unwrap();
        (
            conf_read.resolvers.clone(),
            conf_read.resolver_searching.clone(),
            conf_read.resolver_searching.enable
                && !conf_read.resolver_searching.resolver_source.is_empty(),
            conf_read.relay_conf.clone(),
        )
    };
    if relay_conf.enable {
        relay_conf.key = load_key_from_str(&relay_conf.relay_key)?;
    }
    let relay_conf = Arc::new(relay_conf);
    let resolver_picker = ResolverPicker::new(initial_resolvers, http.clone()).await?;
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
    let cache = Arc::new(new_cache());
    let domain_cache = new_domain_cache();
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
        for (payload, src_addr) in batch {
            let Ok(permit) = resolve_sem.clone().try_acquire_owned() else {
                warn!("reached semaphore maximum");
                continue;
            };
            let redirect_list = redirect_list.load_full();
            let drop_list = drop_list.load_full();
            let http = http.clone();
            let relay_conf = relay_conf.clone();
            let resolver_picker = resolver_picker.clone();
            let server_socket = Arc::clone(&server_socket);
            let cache = Arc::clone(&cache);
            let domain_cache = Arc::clone(&domain_cache);
            // TODO: refactor this part to pass the parameters base on usage
            tokio::spawn(async move {
                let _permit = permit;
                handle_query(
                    &payload,
                    src_addr,
                    &redirect_list,
                    &drop_list,
                    &resolver_picker,
                    &server_socket,
                    &http,
                    &cache,
                    &relay_conf,
                    &domain_cache
                )
                .await;
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
    let resolver_picker = ResolverPicker::new(conf.resolvers, http.clone()).await?;
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

async fn resolve(conf_path: &PathBuf, domain: &str, resolver: Option<String>) -> Result<(), Error> {
    let conf = load_conf(conf_path)?;
    let http = build_http_client()?;
    let resolver_picker = ResolverPicker::new(conf.resolvers, http.clone()).await?;
    let resolved = resolver_picker.resolve(domain, resolver, &http).await?;
    clear_screen();
    if resolved.is_empty() {
        println!(";; no A records found for {domain}");
    } else {
        for ip in resolved {
            println!("\n{domain}.\tIN\tA\t{ip}");
        }
    }

    Ok(())
}
