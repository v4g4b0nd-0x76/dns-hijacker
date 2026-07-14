use dns_hijacker::{
    Error, ResolverPicker, bind_udp_socket, build_http_client,
    conf::watch_conf_and_reload,
    constants::{LOCAL_DNS, PAYLOAD_BUF_SIZE, RECV_BATCH_MAX, RESOLVE_SEMAPHORE},
    handle_query, init_logger, load_conf, new_cache, run_resolver_finder,
};
use std::{
    io,
    path::PathBuf,
    sync::{Arc, RwLock, atomic::AtomicBool},
    time::Duration,
};
use tokio::sync::Semaphore;
use tracing::{error, info, warn};
use arc_swap::ArcSwap;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    init_logger();

    let conf_path = PathBuf::from("conf.toml");
    let conf = Arc::new(RwLock::new(load_conf(&conf_path)?));

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

    let (initial_resolvers, resolver_searching, searching_enabled) = {
        let conf_read = conf.read().unwrap();
        (
            conf_read.resolvers.clone(),
            conf_read.resolver_searching.clone(),
            conf_read.resolver_searching.enable
                && !conf_read.resolver_searching.resolver_source.is_empty(),
        )
    };

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
            let resolver_picker = resolver_picker.clone();
            let server_socket = Arc::clone(&server_socket);
            let cache = Arc::clone(&cache);
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
                )
                .await;
            });
        }
    }
}
