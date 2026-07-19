//! Watches for VPN clients rewriting system DNS or bringing up a tunnel
//! interface, and reasserts our resolver as the system DNS. Platform-specific
//! backends: macOS (networksetup + scutil State: override) and Linux
//! (systemd-resolved via resolvectl, falling back to /etc/resolv.conf).

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

// ============================================================================
// macOS backend
// ============================================================================
#[cfg(target_os = "macos")]
mod platform {
    use super::*;
    use std::process::Stdio;
    use tokio::io::AsyncWriteExt;
    use tracing::debug;

    use crate::constants::{DNS_TARGET, VPN_IFACE_PREFIXES};

    pub async fn tick(is_vpn_active: &Arc<AtomicBool>) -> Result<(), String> {
        let vpn_now = detect_vpn_interface().await?;
        let vpn_was = is_vpn_active.swap(vpn_now, Relaxed);
        if vpn_now != vpn_was {
            info!(
                "[NETGUARD] VPN interface {}",
                if vpn_now { "detected" } else { "no longer detected" }
            );
        }

        if let Some(primary_id) = get_primary_service_id().await {
            if let Err(e) = force_primary_dns_state(&primary_id).await {
                warn!("[NETGUARD] failed to force primary State DNS: {e}");
            } else {
                debug!("[NETGUARD] forced State:/Network/Service/{primary_id}/DNS -> {DNS_TARGET}");
            }
        }

        reassert_dns_on_all_services().await
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

    /// Lists all enabled network services and forces DNS back to 127.0.0.1 on
    /// any that have drifted (VPN client having just overwritten it).
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

    /// Directly overwrites the LIVE (State:) DNS entry for whatever service
    /// configd currently considers primary — this is what Windscribe (and other
    /// VPN clients) hijack to install their own resolver ahead of anything
    /// `networksetup` can touch, since networksetup only writes persistent
    /// Setup: config, not the live State: config configd actually resolves from.
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
    use tokio::fs;
    use tracing::debug;

    use crate::constants::{DNS_TARGET, VPN_IFACE_PREFIXES};

    pub async fn tick(is_vpn_active: &Arc<AtomicBool>) -> Result<(), String> {
        let vpn_now = detect_vpn_interface().await?;
        let vpn_was = is_vpn_active.swap(vpn_now, Relaxed);
        if vpn_now != vpn_was {
            info!(
                "[NETGUARD] VPN interface {}",
                if vpn_now { "detected" } else { "no longer detected" }
            );
        }

        reassert_dns().await
    }

    /// Uses `ip link show` (iproute2, present on essentially every modern
    /// distro) to find VPN-prefixed interfaces that are UP.
    async fn detect_vpn_interface() -> Result<bool, String> {
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
            // e.g. "5: wg0: <POINTOPOINT,UP,LOWER_UP> mtu 1420 ..."
            if let Some(rest) = line.split(": ").nth(1) {
                let name = rest.split(':').next().unwrap_or("").trim();
                let is_vpn = VPN_IFACE_PREFIXES.iter().any(|p| name.starts_with(p));
                let is_up = line.contains("UP,") || line.contains(",UP") || line.contains("<UP>");
                if is_vpn && is_up {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Tries systemd-resolved first (the common case on modern distros); if
    /// `resolvectl` isn't available or the call fails, falls back to writing
    /// /etc/resolv.conf directly.
    async fn reassert_dns() -> Result<(), String> {
        match reassert_via_resolvectl().await {
            Ok(()) => Ok(()),
            Err(resolvectl_err) => {
                debug!("[NETGUARD] resolvectl path unavailable ({resolvectl_err}), falling back to /etc/resolv.conf");
                reassert_via_resolv_conf().await
            }
        }
    }

    async fn reassert_via_resolvectl() -> Result<(), String> {
        // Confirm resolvectl exists / systemd-resolved is actually in charge
        // before we start rewriting things through it.
        let status_output = Command::new("resolvectl")
            .arg("status")
            .output()
            .await
            .map_err(|e| format!("resolvectl not available: {e}"))?;

        if !status_output.status.success() {
            return Err("resolvectl status exited non-zero".into());
        }

        // Apply to every interface resolvectl knows about, same "reassert
        // everywhere" approach as the macOS per-service loop.
        let text = String::from_utf8_lossy(&status_output.stdout);
        let mut touched_any = false;
        for line in text.lines() {
            // Interface sections look like "Link 3 (wlan0)"
            if let Some(iface) = line
                .trim()
                .strip_prefix("Link ")
                .and_then(|s| s.split('(').nth(1))
                .and_then(|s| s.strip_suffix(')'))
            {
                touched_any = true;
                let dns_result = Command::new("resolvectl")
                    .args(["dns", iface, DNS_TARGET])
                    .output()
                    .await
                    .map_err(|e| format!("resolvectl dns failed for {iface}: {e}"))?;

                if dns_result.status.success() {
                    debug!("[NETGUARD] {iface}: resolvectl dns -> {DNS_TARGET}");
                } else {
                    warn!(
                        "[NETGUARD] {iface}: resolvectl dns failed: {}",
                        String::from_utf8_lossy(&dns_result.stderr)
                    );
                }

                // Make our resolver authoritative for ALL domains on this
                // link, not just its DHCP-scoped search domain — otherwise
                // systemd-resolved may still route some queries elsewhere.
                let domain_result = Command::new("resolvectl")
                    .args(["domain", iface, "~."])
                    .output()
                    .await;

                if let Ok(out) = domain_result {
                    if out.status.success() {
                        debug!("[NETGUARD] {iface}: resolvectl domain -> ~. (default route)");
                    }
                }
            }
        }

        if touched_any {
            info!("[NETGUARD] DNS reasserted via resolvectl on all links");
            Ok(())
        } else {
            Err("no links found in resolvectl status output".into())
        }
    }

    /// Last-resort fallback for systems without systemd-resolved: rewrite
    /// /etc/resolv.conf directly. Only touches the file if it has drifted,
    /// to avoid unnecessary writes/log noise every tick.
    async fn reassert_via_resolv_conf() -> Result<(), String> {
        const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";
        let desired = format!("nameserver {DNS_TARGET}\n");

        let current = fs::read_to_string(RESOLV_CONF_PATH).await.unwrap_or_default();
        let already_correct = current
            .lines()
            .any(|l| l.trim() == format!("nameserver {DNS_TARGET}"));

        if already_correct {
            debug!("[NETGUARD] /etc/resolv.conf already points at {DNS_TARGET}, skipping");
            return Ok(());
        }

        fs::write(RESOLV_CONF_PATH, desired)
            .await
            .map_err(|e| format!("failed to write {RESOLV_CONF_PATH}: {e}"))?;

        info!("[NETGUARD] /etc/resolv.conf reasserted to {DNS_TARGET}");
        Ok(())
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
}
