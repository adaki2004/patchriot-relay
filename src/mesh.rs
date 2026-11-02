//! Read-only diagnostics for a Tailscale Serve gateway. No device key is loaded.

use serde::Deserialize;
use std::{
    io::{self, Read},
    net::IpAddr,
    time::Duration,
};

type Error = Box<dyn std::error::Error>;

fn endpoint(value: &str) -> Result<url::Url, Error> {
    let url = url::Url::parse(value).map_err(|_| "invalid mesh dispatcher URL")?;
    let host = url.host_str().unwrap_or("");
    if url.scheme() != "https"
        || !host.ends_with(".ts.net")
        || host.split('.').count() < 4
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
        || url.port() == Some(0)
    {
        return Err("mesh-check needs the HTTPS device.tailnet.ts.net origin from your administrator, without credentials or a path".into());
    }
    Ok(url)
}

fn tailnet_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let bytes = ip.octets();
            bytes[0] == 100 && (64..=127).contains(&bytes[1])
        }
        IpAddr::V6(ip) => ip.segments()[..3] == [0xfd7a, 0x115c, 0xa1e0],
    }
}

#[derive(Deserialize)]
struct Health {
    status: String,
    service: String,
}

fn gateway_reply(bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() > 4096 {
        return Err("gateway health reply exceeds 4 KiB".into());
    }
    let health: Health =
        serde_json::from_slice(bytes).map_err(|_| "gateway health reply is invalid")?;
    if health.status != "ok" || health.service != "patchriot-relay-gateway" {
        return Err(
            "this is not the agent-only Patchriot gateway; ask for its Tailscale address".into(),
        );
    }
    Ok(())
}

pub fn execute(args: &[String]) -> Result<u8, Error> {
    if args.len() != 3 || args[1] != "--dispatcher" {
        return Err("use mesh-check --dispatcher https://device.tailnet.ts.net".into());
    }
    let url = endpoint(&args[2])?.join("/health")?;
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(10))
        .build()?;
    // Only GET /health is sent. Normal certificate validation stays enabled.
    let reply = client.get(url).send().map_err(
        |_| "mesh gateway unreachable: connect Tailscale, check DNS, grants and Serve, then retry",
    )?;
    if !reply
        .remote_addr()
        .is_some_and(|address| tailnet_address(address.ip()))
    {
        return Err("gateway did not use a Tailscale IP; check that DNS resolves through the tailnet and Funnel is disabled".into());
    }
    if !reply.status().is_success() {
        return Err("mesh gateway health check failed; check the Serve target port".into());
    }
    let mut bytes = Vec::new();
    reply
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| "mesh gateway health reply interrupted")?;
    gateway_reply(&bytes)?;
    serde_json::to_writer_pretty(
        io::stdout().lock(),
        &serde_json::json!({
            "reachable": true, "transport": "tailscale_https", "service": "patchriot-relay-gateway",
        "device_approval_checked": false,
            "next": "Network check passed. Pair the device and obtain operator approval separately."
        }),
    )?;
    println!();
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mesh_check_does_not_accept_public_origins_or_credentials() {
        assert!(endpoint("https://dispatcher.example-tail.ts.net").is_ok());
        for url in [
            "http://dispatcher.example-tail.ts.net",
            "https://ts.net",
            "https://example.ts.net",
            "https://dispatcher.example-tail.ts.net.evil.com",
            "https://user@dispatcher.example-tail.ts.net",
            "https://dispatcher.example-tail.ts.net/internal",
            "https://dispatcher.example-tail.ts.net/?key=secret",
            "https://dispatcher.example-tail.ts.net/#fragment",
            "https://100.64.0.1",
            "https://example.com",
        ] {
            assert!(endpoint(url).is_err(), "{url}");
        }
    }
    #[test]
    fn mesh_address_check_covers_both_tailnet_ranges_only() {
        for ip in ["100.64.0.1", "100.127.255.254", "fd7a:115c:a1e0::1"] {
            assert!(tailnet_address(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "100.63.255.255",
            "100.128.0.1",
            "127.0.0.1",
            "1.1.1.1",
            "192.168.1.1",
            "::1",
            "fd7a:115c:a1e1::1",
            "::ffff:100.64.0.1",
        ] {
            assert!(!tailnet_address(ip.parse().unwrap()), "{ip}");
        }
    }
    #[test]
    fn regular_health_or_a_large_reply_cannot_pass_the_mesh_check() {
        assert!(
            gateway_reply(
                br#"{"status":"ok","service":"patchriot-relay-gateway","version":"test"}"#
            )
            .is_ok()
        );
        for bytes in [
            br#"{"status":"ok","version":"test"}"#.as_slice(),
            br#"{"status":"error","service":"patchriot-relay-gateway"}"#,
            b"not json",
            &vec![b' '; 4097],
        ] {
            assert!(gateway_reply(bytes).is_err());
        }
    }
}
