//! Watches for VPN clients rewriting system DNS or bringing up a tunnel
//! interface, and reasserts our resolver as the system DNS. Platform-specific
//! backends: macOS (networksetup + scutil State: override) and Linux
//! (systemd-resolved via resolvectl). Only acts while a VPN interface is
//! actually present, and reverts everything it changed when the VPN goes
//! away or the process shuts down.

use std::sync::{
    atomic::{AtomicBool, Ordering::Relaxed},
    Arc,
};

use tokio::{
    process::Command,
    time::{sleep, Duration},
};
use tracing::{info, warn};

use crate::constants::NETGUARD_POLL_INTERVAL_MS;

/// Runs forever. Call via `tokio::spawn`. Logs and keeps polling even if an
/// individual check fails, since a transient tool hiccup shouldn't kill the guard.
pub async fn run_network_guard(is_vpn_active: Arc<AtomicBool>) {
    let interval = Duration::from_millis(NETGUARD_POLL_INTERVAL_MS);
    info!("[NETGUARD] starting DNS reassertion + VPN detection loop");

    loop {
        if let Err(err) = platform::tick(&is_vpn_active).await {
            warn!("[NETGUARD] tick failed: {err}");
        }
        sleep(interval).await;
    }
}

/// Undoes any DNS overrides netguard has applied. Call this on process
/// shutdown (SIGINT/SIGTERM) so we never leave the system pointed at
/// 127.0.0.1 after this process stops running and can't answer queries.
pub async fn revert() {
    platform::revert().await;
}

// ============================================================================
// macOS backend
// ============================================================================
#[cfg(target_os = "macos")]
mod platform {
    use super::*;
    use std::{
        collections::HashSet,
        process::Stdio,
        sync::OnceLock,
    };
    use tokio::{io::AsyncWriteExt, sync::Mutex as TokioMutex};
    use tracing::debug;

    use crate::constants::{DNS_TARGET, VPN_IFACE_PREFIXES};

    /// Network services we've overridden DNS on, plus whether we've set a
    /// scutil State: override (and for which service id) — needed to revert
    /// exactly what we changed, nothing more.
    struct TouchedState {
        services: HashSet<String>,
        scutil_service_id: Option<String>,
    }

    static TOUCHED: OnceLock<TokioMutex<TouchedState>> = OnceLock::new();

    fn touched() -> &'static TokioMutex<TouchedState> {
        TOUCHED.get_or_init(|| {
            TokioMutex::new(TouchedState {
                services: HashSet::new(),
                scutil_service_id: None,
            })
        })
    }

    pub async fn tick(is_vpn_active: &Arc<AtomicBool>) -> Result<(), String> {
        let vpn_now = detect_vpn_interface().await?;
        let vpn_was = is_vpn_active.swap(vpn_now, Relaxed);

        if vpn_now && !vpn_was {
            info!("[NETGUARD] VPN interface detected");
        } else if !vpn_now && vpn_was {
            info!("[NETGUARD] VPN interface no longer detected — reverting DNS overrides");
            revert().await;
            return Ok(());
        }

        if !vpn_now {
            // No VPN present — leave system DNS exactly as macOS/DHCP set it.
            return Ok(());
        }

        if let Some(primary_id) = get_primary_service_id().await {
            if let Err(e) = force_primary_dns_state(&primary_id).await {
                warn!("[NETGUARD] failed to force primary State DNS: {e}");
            } else {
                debug!("[NETGUARD] forced State:/Network/Service/{primary_id}/DNS -> {DNS_TARGET}");
                touched().await.lock().await.scutil_service_id = Some(primary_id);
            }
        }

        reassert_dns_on_all_services().await
    }

    /// Undoes every override we've applied: clears the scutil State:
    /// override and resets each touched service back to automatic (DHCP) DNS.
    pub async fn revert() {
        let mut state = touched().await.lock().await;

        if let Some(service_id) = state.scutil_service_id.take() {
            let script = format!("remove State:/Network/Service/{service_id}/DNS\n");
            if let Err(e) = run_scutil_script(&script).await {
                warn!("[NETGUARD] failed to remove scutil State override: {e}");
            } else {
                info!("[NETGUARD] removed scutil State:/Network/Service/{service_id}/DNS override");
            }
        }

        for service in state.services.drain() {
            let result = Command::new("networksetup")
                .args(["-setdnsservers", &service, "Empty"])
                .output()
                .await;
            match result {
                Ok(out) if out.status.success() => {
                    info!("[NETGUARD] {service}: DNS reverted to automatic (DHCP)");
                }
                Ok(out) => warn!(
                    "[NETGUARD] {service}: revert failed: {}",
                    String::from_utf8_lossy(&out.stderr)
                ),
                Err(err) => warn!("[NETGUARD] {service}: failed to run networksetup revert: {err}"),
            }
        }
    }

    /// Lists interfaces via `ifconfig` and checks for any VPN-prefixed interface
    /// that's currently UP with an assigned address (actually connected, not
    /// just present-but-down).
    async fn detect_vpn_interface() -> Result<bool, String> {
        let output = Command::new("ifconfig")
            .output()
            .await
            .map_err(|e| format!("ifconfig failed: {e}"))?;

        if !output.status.success() {
            return Err("ifconfig exited non-zero".into());
        }

        let text = String::from_utf8_lossy(&output.stdout);
        let mut current_iface_is_vpn = false;
        let mut current_iface_up = false;

        for line in text.lines() {
            if !line.starts_with(char::is_whitespace) && !line.is_empty() {
                if let Some(name) = line.split(':').next() {
                    current_iface_is_vpn = VPN_IFACE_PREFIXES.iter().any(|p| name.starts_with(p));
                    current_iface_up =
                        line.contains("<UP,") || line.contains(",UP,") || line.contains(",UP>");
                }
                continue;
            }
            if current_iface_is_vpn && current_iface_up && line.trim_start().starts_with("inet ") {
                return Ok(true);
            }
        }

        Ok(false)
    }

    async fn reassert_dns_on_all_services() -> Result<(), String> {
        let list_output = Command::new("networksetup")
            .arg("-listallnetworkservices")
            .output()
            .await
            .map_err(|e| format!("listallnetworkservices failed: {e}"))?;

        if !list_output.status.success() {
            return Err("listallnetworkservices exited non-zero".into());
        }

        let text = String::from_utf8_lossy(&list_output.stdout);
        for line in text.lines().skip(1) {
            let service = line.trim();
            if service.is_empty() || service.starts_with('*') {
                continue;
            }
            reassert_dns_on_service(service).await;
        }

        Ok(())
    }

    async fn reassert_dns_on_service(service: &str) {
        let current = Command::new("networksetup")
            .args(["-getdnsservers", service])
            .output()
            .await;

        let already_correct = match &current {
            Ok(out) if out.status.success() => {
                let text = String::from_utf8_lossy(&out.stdout);
                text.lines().next().map(str::trim) == Some(DNS_TARGET)
            }
            _ => false,
        };

        if already_correct {
            debug!("[NETGUARD] {service}: DNS already {DNS_TARGET}, skipping");
            touched().await.lock().await.services.insert(service.to_string());
            return;
        }

        debug!("[NETGUARD] {service}: reasserting DNS -> {DNS_TARGET}");
        let result = Command::new("networksetup")
            .args(["-setdnsservers", service, DNS_TARGET])
            .output()
            .await;

        match result {
            Ok(out) if out.status.success() => {
                info!("[NETGUARD] {service}: DNS reasserted to {DNS_TARGET}");
                touched().await.lock().await.services.insert(service.to_string());
            }
            Ok(out) => {
                warn!(
                    "[NETGUARD] {service}: setdnsservers failed: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }
            Err(err) => {
                warn!("[NETGUARD] {service}: failed to run networksetup: {err}");
            }
        }
    }

    async fn run_scutil_script(script: &str) -> Result<String, String> {
        let mut child = Command::new("scutil")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| format!("failed to spawn scutil: {e}"))?;

        if let Some(stdin) = child.stdin.as_mut() {
            stdin
                .write_all(script.as_bytes())
                .await
                .map_err(|e| format!("failed to write scutil script: {e}"))?;
        }

        let output = child
            .wait_with_output()
            .await
            .map_err(|e| format!("scutil wait failed: {e}"))?;
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    async fn get_primary_service_id() -> Option<String> {
        let out = run_scutil_script("show State:/Network/Global/IPv4\n")
            .await
            .ok()?;
        out.lines()
            .find_map(|l| l.trim().strip_prefix("PrimaryService : "))
            .map(|s| s.trim().to_string())
    }

    async fn force_primary_dns_state(service_id: &str) -> Result<(), String> {
        let script = format!(
            "d.init\nd.add ServerAddresses * {DNS_TARGET}\nset State:/Network/Service/{service_id}/DNS\n"
        );
        run_scutil_script(&script).await?;
        Ok(())
    }
}

// ============================================================================
// Linux backend
// ============================================================================
#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use std::{collections::HashSet, sync::OnceLock};
    use tokio::sync::Mutex as TokioMutex;
    use tracing::debug;

    use crate::constants::{DNS_TARGET, VPN_IFACE_PREFIXES};

    /// Interfaces we've set DNS on via resolvectl — tracked so `revert()`
    /// touches exactly these, nothing else (never docker0/br-*/veth*, etc).
    static TOUCHED_LINKS: OnceLock<TokioMutex<HashSet<String>>> = OnceLock::new();

    async fn touched_links() -> &'static TokioMutex<HashSet<String>> {
        TOUCHED_LINKS.get_or_init(|| TokioMutex::new(HashSet::new()))
    }

    pub async fn tick(is_vpn_active: &Arc<AtomicBool>) -> Result<(), String> {
        let vpn_iface = detect_vpn_interface().await?;
        let vpn_now = vpn_iface.is_some();
        let vpn_was = is_vpn_active.swap(vpn_now, Relaxed);

        if vpn_now && !vpn_was {
            info!("[NETGUARD] VPN interface detected: {}", vpn_iface.as_deref().unwrap_or("?"));
        } else if !vpn_now && vpn_was {
            info!("[NETGUARD] VPN interface no longer detected — reverting DNS overrides");
            revert().await;
            return Ok(());
        }

        if !vpn_now {
            // No VPN present — leave system DNS exactly as NetworkManager/
            // systemd-resolved/DHCP set it. This is what fixes the
            // "keeps reasserting on docker0/br-*/veth* forever" bug: we
            // simply do nothing at all when there's no VPN to fight.
            return Ok(());
        }

        // Only ever touch the VPN's own interface and whichever interface
        // currently owns the default route — never every link resolvectl
        // happens to know about (that was the bug: docker0/br-*/veth* were
        // getting DNS rewritten even though they're irrelevant).
        let mut targets: HashSet<String> = HashSet::new();
        if let Some(v) = vpn_iface {
            targets.insert(v);
        }
        if let Some(d) = get_default_route_iface().await {
            targets.insert(d);
        }

        if targets.is_empty() {
            return Err("no target interface found for DNS reassertion".into());
        }

        reassert_via_resolvectl(&targets).await
    }

    /// Undoes DNS overrides on every interface we've touched, via
    /// `resolvectl revert`, which resets a link's DNS config back to
    /// whatever the network manager/DHCP would normally set.
    pub async fn revert() {
        let mut set = touched_links().await.lock().await;
        for iface in set.drain() {
            let result = Command::new("resolvectl").args(["revert", &iface]).output().await;
            match result {
                Ok(out) if out.status.success() => {
                    info!("[NETGUARD] {iface}: DNS reverted via resolvectl");
                }
                Ok(out) => warn!(
                    "[NETGUARD] {iface}: resolvectl revert failed: {}",
                    String::from_utf8_lossy(&out.stderr)
                ),
                Err(err) => warn!("[NETGUARD] {iface}: failed to run resolvectl revert: {err}"),
            }
        }
    }

    /// Returns the VPN-prefixed interface name if one is UP, via `ip link show`.
    async fn detect_vpn_interface() -> Result<Option<String>, String> {
        let output = Command::new("ip")
            .args(["link", "show"])
            .output()
            .await
            .map_err(|e| format!("ip link show failed: {e}"))?;

        if !output.status.success() {
            return Err("ip link show exited non-zero".into());
        }

        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            if let Some(rest) = line.split(": ").nth(1) {
                let name = rest.split(':').next().unwrap_or("").trim();
                let is_vpn = VPN_IFACE_PREFIXES.iter().any(|p| name.starts_with(p));
                let is_up = line.contains("UP,") || line.contains(",UP") || line.contains("<UP>");
                if is_vpn && is_up {
                    return Ok(Some(name.to_string()));
                }
            }
        }

        Ok(None)
    }

    /// Finds the interface currently holding the default route, via
    /// `ip route show default`. This is the interface that would normally
    /// carry DNS traffic — we want it pinned to 127.0.0.1 while a VPN
    /// (which may install its own resolver on this same interface, or a
    /// separate tunnel interface) is active.
    async fn get_default_route_iface() -> Option<String> {
        let output = Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .await
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let text = String::from_utf8_lossy(&output.stdout);
        // e.g. "default via 192.168.1.1 dev enp4s0 proto dhcp metric 100"
        let mut parts = text.split_whitespace();
        while let Some(tok) = parts.next() {
            if tok == "dev" {
                return parts.next().map(str::to_string);
            }
        }
        None
    }

    /// Sets DNS + default-route domain on exactly the given interfaces,
    /// skipping any that already report 127.0.0.1 to avoid redundant calls
    /// and log spam every tick.
    async fn reassert_via_resolvectl(targets: &HashSet<String>) -> Result<(), String> {
        // Sanity check resolvectl/systemd-resolved is actually present
        // before we start issuing per-interface calls.
        let status_output = Command::new("resolvectl")
            .arg("status")
            .output()
            .await
            .map_err(|e| format!("resolvectl not available: {e}"))?;
        if !status_output.status.success() {
            return Err("resolvectl status exited non-zero".into());
        }

        for iface in targets {
            if is_already_correct(iface).await {
                debug!("[NETGUARD] {iface}: DNS already {DNS_TARGET}, skipping");
                touched_links().await.lock().await.insert(iface.clone());
                continue;
            }

            let dns_result = Command::new("resolvectl")
                .args(["dns", iface, DNS_TARGET])
                .output()
                .await
                .map_err(|e| format!("resolvectl dns failed for {iface}: {e}"))?;

            if dns_result.status.success() {
                info!("[NETGUARD] {iface}: DNS reasserted to {DNS_TARGET}");
                touched_links().await.lock().await.insert(iface.clone());
            } else {
                warn!(
                    "[NETGUARD] {iface}: resolvectl dns failed: {}",
                    String::from_utf8_lossy(&dns_result.stderr)
                );
                continue;
            }

            let domain_result = Command::new("resolvectl")
                .args(["domain", iface, "~."])
                .output()
                .await;
            if let Ok(out) = domain_result && out.status.success() {
                debug!("[NETGUARD] {iface}: resolvectl domain -> ~. (default route)");
            }
        }

        Ok(())
    }

    async fn is_already_correct(iface: &str) -> bool {
        let Ok(out) = Command::new("resolvectl").args(["dns", iface]).output().await else {
            return false;
        };
        if !out.status.success() {
            return false;
        }
        String::from_utf8_lossy(&out.stdout).contains(DNS_TARGET)
    }
}

// ============================================================================
// Fallback for any other OS: no-op, logs once.
// ============================================================================
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod platform {
    use super::*;

    pub async fn tick(_is_vpn_active: &Arc<AtomicBool>) -> Result<(), String> {
        Err("netguard is only implemented for macOS and Linux".into())
    }

    pub async fn revert() {}
}
