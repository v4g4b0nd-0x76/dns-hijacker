use std::{io, sync::Arc};

use tokio::sync::Semaphore;
use tracing::{info, error,warn};
use dns_hijacker::{
    bind_udp_socket, build_http_client, handle_query, load_conf, new_cache, init_logger, ResolverPicker,
    constants::{LOCAL_DNS, PAYLOAD_BUF_SIZE, RECV_BATCH_MAX, RESOLVE_SEMAPHORE},
    Error,
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    let conf = Arc::new(load_conf()?);
    let _logger = init_logger();
    let http = build_http_client()?;
    let resolver_picker = ResolverPicker::new(conf.resolvers.clone(), http.clone()).await?;
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

        // Drain ready datagrams in one wakeup to cut recv syscalls under burst load.
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

            let conf = Arc::clone(&conf);
            let http = http.clone();
            let resolver_picker = resolver_picker.clone();
            let server_socket = Arc::clone(&server_socket);
            let cache = Arc::clone(&cache);

            tokio::spawn(async move {
                let _permit = permit;
                handle_query(
                    &payload,
                    src_addr,
                    &conf,
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
