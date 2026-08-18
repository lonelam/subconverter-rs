# 作为库与 WASM 使用

## Rust 库（crates.io）

crate 名为 [`subconverter`](https://crates.io/crates/subconverter)（库名 `libsubconverter`）：

```toml
[dependencies]
subconverter = "0.2"
```

核心入口是 `SubconverterConfigBuilder` + `subconverter()`，与 HTTP API 走同一条管线：

```rust
use libsubconverter::interfaces::subconverter::{subconverter, SubconverterConfigBuilder};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), String> {
    let mut builder = SubconverterConfigBuilder::new();
    builder
        .target_from_str("clash")
        .add_url("ss://YWVzLTI1Ni1nY206dGVzdA==@example.com:8388#node")
        .add_emoji(true);

    let result = subconverter(builder.build()?).await?;
    println!("{}", result.content);
    Ok(())
}
```

builder 上可链式设置与 HTTP 参数一一对应的选项（`include_remarks`、`rename`、`udp`、`clash_flavor`、`update_interval` 等）。更底层的解析/生成也可以单独使用：

- `parser::explodes::explode(&link, &mut proxy)` — 单条分享链接 → `Proxy`
- `parser::explodes::explode_clash(&yaml, &mut nodes)` — Clash YAML → 节点列表
- `models::clash::ClashProxy::from_proxy(&proxy)` — 节点 → Clash 双向 schema
- `generator::exports::proxy_to_clash::proxy_to_clash(...)` 等各目标 emitter

> 说明：非 wasm 构建默认不含 HTTP 服务器（`web-api` 特性才有）；库本身可用在任意 tokio 程序中，HTTP 拉取订阅使用 awc（需在 `LocalSet` 中运行）。

## npm 包（WASM）

[`subconverter-wasm`](https://www.npmjs.com/package/subconverter-wasm) 是同一套 Rust 代码的 `wasm32` 构建（`--target nodejs`），面向 Node.js / Serverless：

```js
const wasm = require('subconverter-wasm');

// 初始化 KV 绑定与配置（Serverless 环境下文件读写走 KV 虚拟文件系统）
wasm.admin_init_kv_bindings_js();
await wasm.init_settings_wasm('/pref.yml');

// 与 /sub 相同的参数，以 JSON 传入
const resp = await wasm.sub_process_wasm(JSON.stringify({
    target: 'clash',
    url: 'https://example.com/sub',
    emoji: true,
}));
```

主要导出：

| 函数 | 说明 |
|------|------|
| `sub_process_wasm(query_json)` | 订阅转换（等价 `/sub`，返回 Promise） |
| `init_settings_wasm(pref_path)` | 加载服务端配置 |
| `admin_read_file` / `admin_write_file` / `list_directory` … | 虚拟文件系统管理（配置、规则文件） |
| `admin_load_github_directory(path)` | 从 GitHub 懒加载缺失的 base 配置/规则 |
| 短链接、规则更新等 | 见包的 `.d.ts` 类型定义 |

在 WASM 环境中"文件"读写通过 **KV 虚拟文件系统**（Netlify Blobs / Vercel KV）完成，缺失的 `base/` 文件会自动从 GitHub 拉取。

## 自部署 Netlify（Web GUI + Serverless API）

`www/` 目录即在线服务的完整实现（Next.js 15 + `subconverter-wasm`）：

1. Fork 本仓库，在 Netlify 新建站点指向 fork，设置 base directory 为 `www`（`www/netlify.toml` 已含构建配置）
2. Netlify 会构建 Next.js 前端，并把 `/api/*` 作为 Serverless Functions 运行 WASM 转换
3. 启用 Netlify Blobs 后短链接与在线配置编辑即可用

本地开发：

```bash
cd www
pnpm install
pnpm dev              # 使用 npm 上已发布的 subconverter-wasm
pnpm rebuild:wasm:dev # 或者：本地重新构建 wasm 后再启动（需 wasm-pack、jq）
```

## 版本对应关系

`Cargo.toml` 的版本驱动一切：`www/package.json` 锁定同版本的 `subconverter-wasm`。发版用 `./scripts/build-wasm.sh --bump-patch`，会自动提交并推送 `v{X.Y.Z}-attempt{N}` 标签，触发 GitHub Actions 发布 npm 包、crates.io、各平台二进制与 Docker 镜像。
