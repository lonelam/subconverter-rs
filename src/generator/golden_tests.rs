//! Golden output tests for every proxy emitter.
//!
//! These tests lock the emitted configuration for a fixed, diverse node set.
//! They are the safety net for refactoring the generator layer: any change to
//! the output of any target format shows up as a golden diff.
//!
//! To intentionally update the expected outputs run:
//! `cargo test --lib regenerate_goldens -- --ignored`

use crate::generator::config::formats::loon::proxy_to_loon;
use crate::generator::config::formats::mellow::proxy_to_mellow;
use crate::generator::config::formats::quan::proxy_to_quan;
use crate::generator::config::formats::quanx::proxy_to_quanx;
use crate::generator::config::formats::singbox::proxy_to_singbox;
use crate::generator::config::formats::single::{proxy_to_single, ProxyUriTypes};
use crate::generator::config::formats::ss_sub::proxy_to_ss_sub;
use crate::generator::config::formats::ssd::proxy_to_ssd;
use crate::generator::config::formats::surge::proxy_to_surge;
use crate::generator::exports::proxy_to_clash::proxy_to_clash;
use crate::models::ExtraSettings;
use crate::parser::explodes::explode_clash;
use crate::Proxy;
use std::path::PathBuf;

/// A fixture subscription covering every supported protocol with the fields
/// that historically got lost in conversion. Collection-valued fields are kept
/// single-element so emitter output stays deterministic.
const FIXTURE_CLASH_YAML: &str = r#"
proxies:
  - {name: "ss-plain", type: ss, server: ss.example.com, port: 8388, cipher: aes-256-gcm, password: "pass:word=", udp: true}
  - {name: "ssr-node", type: ssr, server: ssr.example.com, port: 8389, cipher: aes-128-cfb, password: ssrpass, protocol: auth_aes128_md5, protocol-param: "1234:abc", obfs: http_simple, obfs-param: obfs.example.com}
  - {name: "vmess-ws", type: vmess, server: vmess.example.com, port: 443, uuid: b445361a-abcf-4a4a-a97a-0bf4136d6ddc, alterId: 0, cipher: auto, udp: true, tls: true, network: ws, servername: sni.example.com, ws-opts: {path: /ws, headers: {Host: host.example.com}}}
  - {name: "trojan-node", type: trojan, server: trojan.example.com, port: 443, password: trojanpw, udp: true, sni: tsni.example.com, alpn: [h2], skip-cert-verify: false, client-fingerprint: chrome}
  - {name: "vless-reality", type: vless, server: vless.example.com, port: 8443, uuid: 56b8aaaa-c339-4502-86ae-9d2a20dcbbbb, network: grpc, tls: true, udp: true, flow: xtls-rprx-vision, client-fingerprint: chrome, servername: addons.mozilla.org, grpc-opts: {grpc-service-name: grpc}, reality-opts: {public-key: bY9DOyBwDrix8ArirlAd, short-id: "0123"}}
  - {name: "hysteria-node", type: hysteria, server: hy1.example.com, port: 62003, auth-str: hyauth, up: "1000 Mbps", down: "1000 Mbps", protocol: udp, sni: hsni.example.com, skip-cert-verify: true, alpn: [h3]}
  - {name: "hysteria2-node", type: hysteria2, server: hy2.example.com, port: 443, password: hy2pass, obfs: salamander, obfs-password: obfspw, sni: h2sni.example.com, alpn: [h3]}
  - {name: "snell-node", type: snell, server: snell.example.com, port: 44046, psk: snellpsk, version: 3, obfs-opts: {mode: http, host: bing.com}}
  - {name: "http-node", type: http, server: http.example.com, port: 8080, username: httpuser, password: httppass}
  - {name: "socks-node", type: socks5, server: socks.example.com, port: 1080, username: sockuser, password: sockpass, udp: true}
  - {name: "wg-node", type: wireguard, server: wg.example.com, port: 51820, private-key: cHJpdmF0ZWtleQ==, public-key: cHVibGlja2V5, ip: 10.0.0.2, dns: [1.1.1.1], mtu: 1420, udp: true}
  - {name: "anytls-node", type: anytls, server: anytls.example.com, port: 8443, password: anytlspw, sni: asni.example.com, client-fingerprint: chrome, udp: true}
"#;

const CLASH_BASE: &str = "mixed-port: 7890\nmode: rule\n";

fn fixture_nodes() -> Vec<Proxy> {
    let mut nodes = Vec::new();
    assert!(
        explode_clash(FIXTURE_CLASH_YAML, &mut nodes),
        "fixture must parse"
    );
    assert_eq!(nodes.len(), 12, "all fixture nodes must parse");
    nodes
}

fn ext_nodelist() -> ExtraSettings {
    let mut ext = ExtraSettings::default();
    ext.nodelist = true;
    ext.enable_rule_generator = false;
    ext
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future)
}

/// Produce the output of every emitter for the fixture node set.
fn generate_all() -> Vec<(&'static str, String)> {
    let mut outputs = Vec::new();

    {
        let mut nodes = fixture_nodes();
        let mut ext = ext_nodelist();
        outputs.push((
            "clash_nodelist",
            proxy_to_clash(&mut nodes, "", &mut Vec::new(), &Vec::new(), false, &mut ext),
        ));
    }
    {
        let mut nodes = fixture_nodes();
        let mut ext = ExtraSettings::default();
        ext.enable_rule_generator = false;
        outputs.push((
            "clash_full",
            proxy_to_clash(
                &mut nodes,
                CLASH_BASE,
                &mut Vec::new(),
                &Vec::new(),
                false,
                &mut ext,
            ),
        ));
    }
    {
        let mut nodes = fixture_nodes();
        let mut ext = ext_nodelist();
        outputs.push((
            "surge4_nodelist",
            block_on(proxy_to_surge(
                &mut nodes,
                "",
                &mut Vec::new(),
                &Vec::new(),
                4,
                &mut ext,
            )),
        ));
    }
    {
        let mut nodes = fixture_nodes();
        let mut ext = ExtraSettings::default();
        ext.enable_rule_generator = false;
        outputs.push((
            "quanx_full",
            block_on(proxy_to_quanx(
                &mut nodes,
                "[general]\n",
                &mut Vec::new(),
                &Vec::new(),
                &mut ext,
            )),
        ));
    }
    {
        let mut nodes = fixture_nodes();
        let mut ext = ext_nodelist();
        outputs.push((
            "loon_nodelist",
            block_on(proxy_to_loon(
                &mut nodes,
                "",
                &mut Vec::new(),
                &Vec::new(),
                &mut ext,
            )),
        ));
    }
    {
        let mut nodes = fixture_nodes();
        let mut ext = ext_nodelist();
        outputs.push((
            "singbox_nodelist",
            proxy_to_singbox(&mut nodes, "", &mut Vec::new(), &Vec::new(), &mut ext),
        ));
    }
    {
        let mut nodes = fixture_nodes();
        let mut ext = ExtraSettings::default();
        ext.enable_rule_generator = false;
        outputs.push((
            "mellow_full",
            block_on(proxy_to_mellow(
                &mut nodes,
                "[Endpoint]\n",
                &mut Vec::new(),
                &Vec::new(),
                &mut ext,
            )),
        ));
    }
    {
        let mut nodes = fixture_nodes();
        let mut ext = ExtraSettings::default();
        ext.enable_rule_generator = false;
        outputs.push((
            "quan_full",
            block_on(proxy_to_quan(
                &mut nodes,
                "[SERVER]\n",
                &mut Vec::new(),
                &Vec::new(),
                &mut ext,
            )),
        ));
    }
    {
        let mut nodes = fixture_nodes();
        let mut ext = ext_nodelist();
        outputs.push(("ss_sub", proxy_to_ss_sub("{}", &mut nodes, &mut ext)));
    }
    {
        let mut nodes = fixture_nodes();
        let ext = ExtraSettings::default();
        outputs.push(("ssd", proxy_to_ssd(&mut nodes, "TestGroup", "", &ext)));
    }
    {
        let mut nodes = fixture_nodes();
        let mut ext = ext_nodelist();
        outputs.push((
            "single_mixed",
            proxy_to_single(&mut nodes, ProxyUriTypes::MIXED, &mut ext),
        ));
    }

    outputs
}

fn golden_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src/generator/testdata")
        .join(format!("{}.golden", name))
}

#[test]
fn golden_outputs_match() {
    let mut failures = Vec::new();
    for (name, actual) in generate_all() {
        let path = golden_path(name);
        let expected = std::fs::read_to_string(&path).unwrap_or_else(|_| {
            panic!(
                "missing golden file {:?}; run `cargo test --lib regenerate_goldens -- --ignored`",
                path
            )
        });
        if actual != expected {
            failures.push(format!(
                "golden mismatch for '{}'\n--- expected ---\n{}\n--- actual ---\n{}",
                name, expected, actual
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}

/// Deterministic-output guard: two runs in the same process must agree.
#[test]
fn golden_outputs_are_deterministic() {
    let first = generate_all();
    let second = generate_all();
    for ((name, a), (_, b)) in first.iter().zip(second.iter()) {
        assert_eq!(a, b, "output of '{}' is nondeterministic", name);
    }
}

#[test]
#[ignore]
fn regenerate_goldens() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/generator/testdata");
    std::fs::create_dir_all(&dir).unwrap();
    for (name, actual) in generate_all() {
        std::fs::write(golden_path(name), actual).unwrap();
    }
}
