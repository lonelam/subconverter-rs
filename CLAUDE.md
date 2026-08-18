# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Rust rewrite of the C++ subconverter: converts proxy subscriptions between formats (Clash, Surge, sing-box, V2Ray, Quantumult X, Loon, etc.). One crate builds three ways:

1. **Native HTTP server / CLI** — binary `subconverter` (actix-web, port 25500). The binary requires the `web-api` feature; plain `cargo build` compiles only the library.
2. **Rust library** — `libsubconverter` (rlib).
3. **WASM package** — `subconverter-wasm` npm package (cdylib via wasm-pack, `--target nodejs`), consumed by the Next.js frontend in `www/` and deployed as Netlify serverless functions.

## Commands

```bash
# Build / run the server (web-api feature is required for the binary)
cargo build --release --features web-api
cargo run --features web-api                 # server on 127.0.0.1:25500

# One-shot conversion without a server (--url is a request URI, routed through the same handlers)
cargo run --features web-api -- --url "/sub?target=clash&url=..." -o output.yaml

# Tests (inline #[cfg(test)] modules; no tests/ directory)
cargo test
cargo test some_test_name                    # single test by name substring

# Type-check the wasm side (rustup target add wasm32-unknown-unknown first)
cargo check --target wasm32-unknown-unknown

# WASM dev build: wasm-pack build, rename to subconverter-wasm, copy into www/node_modules/
./scripts/build-wasm.sh                      # needs wasm-pack, jq, pnpm

# Frontend (www/, Node >= 20, pnpm)
cd www && pnpm install && pnpm dev
pnpm rebuild:wasm:dev                        # rebuild wasm then start dev server
pnpm lint
```

Optional cargo feature `js-runtime` (rquickjs, non-wasm only) enables JS scripting support; CI release builds use `--features=web-api,js-runtime`.

## Release flow

Version in `Cargo.toml` drives everything; `www/package.json` pins the matching `subconverter-wasm` version. `./scripts/build-wasm.sh --bump-patch` bumps the version, commits, and pushes a `v{X.Y.Z}-attempt{N}` tag that triggers the GitHub Actions release (npm + crates.io + binaries). `--bump-beta` (non-main branch only) publishes an npm beta and deploys a Netlify preview. Both require a clean git tree.

## Architecture

The conversion pipeline is **parse → transform → generate**, orchestrated in `src/interfaces/subconverter.rs` (`SubconverterConfig` / `subconverter()`). Both the native web handlers and the WASM API funnel through this one entry point.

- `src/parser/` — input side. `explodes/` has one module per input format ("explode" = raw link/config text → `Proxy` structs): ss, ssr, vmess, vless, trojan, hysteria/hysteria2, wireguard, snell, anytls, surge, clash, etc. `subparser.rs::add_nodes` fetches subscription URLs and dispatches to the right explode. Clash YAML is parsed per-entry (one malformed node is skipped, not the whole subscription).
- `src/models/` — core domain types shared by both sides.
  - `proxy.rs` — `Proxy` carries only cross-protocol fields (endpoint, udp/tfo flags, the TLS block: `tls_secure`/`sni`/`alpn`/`fingerprint`/`client_fingerprint`). All protocol-specific data lives in `proxy_node/` structs under the `CombinedProxy` enum — each piece of information has exactly one home. Typed access via `as_vmess()`-style accessors plus cross-protocol view methods (`password()`, `host()`, `obfs()`, …).
  - `clash/` — the bidirectional Clash schema: one `Serialize + Deserialize` struct per protocol used for BOTH parsing and generation, so parse → emit roundtrips are lossless by construction (see the idempotence test in `clash/mod.rs`). `ClashProxyYamlInput` (parser) and `ClashProxyOutput` (generator) are aliases of this shared `ClashProxy` enum.
  - `target_profile.rs` — `ClashFlavor` (mihomo/premium/stash, chosen by the `flavor=` query param) and the `ClashCapabilities` matrix. `proxy_to_clash` consults it to drop unsupported protocols and strip unsupported fields per flavor. Client-version differences belong here, not in scattered conditionals.
- `src/generator/` — output side. `config/formats/` has one module per target (`proxy_to_surge`, `proxy_to_singbox`, …) plus `exports/proxy_to_clash.rs`; `ruleconvert/` converts rulesets between target formats. Emitters read protocol data only through the typed IR accessors.
  - `golden_tests.rs` + `testdata/*.golden` — golden output tests: a 12-protocol fixture rendered through every emitter, byte-compared against checked-in files. Any output change shows up as a golden diff; update intentionally with `cargo test --lib regenerate_goldens -- --ignored`.
- `src/web_handlers/` (`web-api` feature) — actix-web endpoints (`/sub`, `/surge2clash`, …). `main.rs` starts the server; CLI direct mode routes a synthetic request through the same handlers via actix's test service.
- `src/api/` — WASM-facing `#[wasm_bindgen]` exports (sub, admin, rules, short_urls; mostly `cfg(target_arch = "wasm32")`).
- `src/vfs/` (wasm only) — virtual file system over Vercel KV / Netlify Blobs through JS bindings in `js/kv_bindings.js`, with lazy loading of missing files from GitHub. In the WASM build, "file" reads for configs/rules go through this.
- `src/settings/` — global `Settings` singleton (`Settings::current()`); loads `pref.toml` → `pref.yml` → `pref.ini` in that priority order. `external/` handles the `&config=` external configs.
- `src/template/` — minijinja-based template rendering for base configs.
- `base/` — runtime data, not code: example prefs, base config templates, rules, snippets. The server reads these at runtime.
- `www/` — Next.js 15 App Router frontend (TypeScript, Tailwind 4, next-intl); calls `subconverter-wasm` from Netlify functions. Deployed via `www/netlify.toml`.

### Dual-target constraint

Conditional compilation on `cfg(target_arch = "wasm32")` is pervasive: native uses awc + tokio for HTTP and real filesystem access; wasm uses web-sys fetch and the KV-backed VFS. When touching shared code (parser, generator, settings, utils), keep both targets compiling — check with `cargo check` and `cargo check --target wasm32-unknown-unknown`.
