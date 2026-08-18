# 支持的协议与目标格式

## 输入：能解析什么

**分享链接**（单条或 base64 订阅中的行）：

| 协议 | 链接形式 |
|------|----------|
| Shadowsocks | `ss://`（SIP002 与旧格式；AEAD-2022 明文 userinfo 会正确 URL 解码） |
| ShadowsocksR | `ssr://` |
| VMess | `vmess://`（含标准 JSON、Shadowrocket、Kitsunebi 等多种方言） |
| VLESS | `vless://`（含 Reality、gRPC/ws/h2 传输、flow） |
| Trojan | `trojan://`（含 trojan-go 参数） |
| Hysteria | `hysteria://` |
| Hysteria2 | `hysteria2://`、`hy2://` |
| TUIC v5 | `tuic://uuid:password@host:port?...` |
| AnyTLS | `anytls://password@host:port?...` |
| Snell | `snell://` |
| WireGuard | `wg://`、`wireguard://` |
| HTTP/Socks | `http(s)://`、`socks://`、Telegram 式 `tg://socks` 链接 |

**完整配置文件 / 订阅格式**：Clash YAML（`proxies:`）、Surge 配置、base64 通用订阅、SSD（`ssd://`）、SS Android/GUI JSON、Netch、SSTap、V2Ray 配置等。

> Clash YAML 采用**逐节点容错**解析：某个节点字段不合法只会跳过该节点并记录日志，不会导致整个订阅失败。

## 输出：目标格式 × 协议矩阵

| 协议 | clash (mihomo) | singbox | surge (≥4) | quanx | loon | quan | mellow | mixed 链接 | ssd / sssub |
|------|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Shadowsocks | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| ShadowsocksR | ✅ | ✅ | ✅* | ✅ | ✅ | ✅ | — | ✅ | ✅** |
| VMess | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| VLESS (含 Reality) | ✅ | ✅ | — | — | — | — | — | — | — |
| Trojan | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | ✅ | — |
| Snell (≤v3) | ✅ | — | ✅ | — | — | — | — | — | — |
| HTTP/HTTPS | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — | — |
| SOCKS5 | ✅ | ✅ | ✅ | ✅ | — | ✅ | ✅ | — | — |
| WireGuard | ✅ | ✅ | ✅ | — | ✅ | — | — | — | — |
| Hysteria | ✅ | ✅ | — | — | — | — | — | — | — |
| Hysteria2 | ✅ | ✅ | ✅ | — | — | — | — | — | — |
| TUIC v5 | ✅ | ✅ | — | — | — | — | — | — | — |
| AnyTLS | ✅ | ✅ | — | — | — | — | — | — | — |

\* Surge 的 SSR 需要在服务端配置 `surge_ssr_path` 外部二进制。
\*\* SSD/SSSub 输出仅收录能降级为标准 SS 的 SSR 节点（`origin` + `plain`）。

不支持的协议节点会被对应目标**静默跳过**，不会产生客户端无法加载的配置。

## Clash 内核流派能力矩阵（`flavor=`）

同为 "Clash 配置"，不同内核接受的字段并不一样。`flavor=` 参数让输出精确匹配目标内核：

| 能力 | `mihomo`（默认） | `premium` | `stash` |
|------|:---:|:---:|:---:|
| VLESS / Reality | ✅ | ❌ 节点剔除 | ✅ |
| Hysteria / Hysteria2 | ✅ | ❌ 节点剔除 | ✅ |
| TUIC | ✅ | ❌ 节点剔除 | ✅ |
| AnyTLS | ✅ | ❌ 节点剔除 | ❌ 节点剔除 |
| uTLS `client-fingerprint` | ✅ | ❌ 字段剥离 | ❌ 字段剥离 |
| `udp-over-tcp` | ✅ | ❌ 字段剥离 | ❌ 字段剥离 |

- **节点剔除**：该协议节点整体不出现在输出里（残缺的节点只会让内核报错）
- **字段剥离**：节点保留，但删除该内核不认识的字段
- Reality 节点在不支持 Reality 的内核上会整体剔除（没有 reality-opts 的 Reality 节点无法使用）

示例：`/sub?target=clash&flavor=stash&url=...`

## sing-box 输出说明

sing-box 出站覆盖：shadowsocks、shadowsocksr、vmess、trojan、wireguard、hysteria、hysteria2、**vless（含 Reality + uTLS + ws/grpc/http 传输）**、**tuic**、**anytls**、http、socks。TLS 块统一携带 `server_name`、`alpn`、`insecure`、`utls`、`reality` 设置。
