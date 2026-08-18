# subconverter-rs Wiki

subconverter-rs 是 C++ 版 [subconverter](https://github.com/tindy2013/subconverter) 的 Rust 重写版：在各种代理订阅格式之间互相转换（Clash/mihomo、Surge、sing-box、Quantumult X、Loon、V2Ray 等），一套代码同时提供原生 HTTP 服务、命令行工具、Rust 库和可部署到 Serverless 的 WASM 包。

## 五种使用方式一览

| 方式 | 适合场景 | 入口 |
|------|----------|------|
| **在线服务** | 直接用，无需部署 | <https://subconverter-rs.netlify.app> |
| **HTTP API 服务器** | 自托管，供订阅客户端定期拉取 | 二进制 / Docker，默认端口 `25500` |
| **命令行一次性转换** | 脚本化、离线生成配置文件 | `subconverter --url "/sub?..." -o out.yaml` |
| **Rust 库** | 在自己的 Rust 项目里做格式转换 | crates.io 上的 [`subconverter`](https://crates.io/crates/subconverter) crate |
| **WASM / npm 包** | 在 Node.js / Serverless（Netlify、Vercel）里跑转换 | npm 上的 [`subconverter-wasm`](https://www.npmjs.com/package/subconverter-wasm) |

## 文档目录

- [快速开始](Getting-Started.md) — 在线服务、下载二进制、Docker、源码构建、服务器配置与命令行模式
- [HTTP API 参数详解](HTTP-API.md) — `/sub` 接口的全部查询参数
- [支持的协议与目标格式](Protocols-and-Targets.md) — 输入协议 × 输出格式支持矩阵、Clash 内核流派（flavor）能力矩阵
- [进阶用法](Advanced-Usage.md) — 外部配置、节点筛选语法、重命名与 Emoji、定时任务、Web GUI 与短链接
- [作为库与 WASM 使用](Library-and-WASM.md) — Rust crate、npm 包、Netlify 自部署

## 与 C++ 版的关系

调用方式与参数尽量保持与 C++ 版兼容（`/sub?target=...&url=...` 的链接可以直接换域名使用），并在此基础上增加了：

- `flavor=` 参数区分 Clash 内核流派（mihomo / Premium / Stash），按目标客户端自动剔除其无法加载的协议和字段
- AnyTLS、TUIC v5 等新协议的解析与输出
- sing-box 输出（含 VLESS Reality、TUIC、AnyTLS 出站）
- 单节点解析失败不再导致整个订阅解析失败（逐节点容错）
- Next.js Web GUI 与短链接服务（`www/`，可部署到 Netlify）

尚未实现的 C++ 功能：Clash Script 渲染（`&script=` 的脚本模式）、`script:` 节点脚本处理。JS 脚本相关参数（`filter=`、`sort_script=`）需要以 `js-runtime` 特性构建的二进制。
