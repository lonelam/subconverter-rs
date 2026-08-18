# HTTP API 参数详解

核心接口：

```
GET /sub?target=<目标格式>&url=<订阅链接>&<其他参数>
```

- `url` 中的订阅链接必须 **URL 编码**；多条订阅用 `|` 连接后整体编码
- 布尔参数接受 `true/false`、`1/0`、`yes/no`、`on/off`
- 数字参数同时接受数字与字符串形式（`interval=86400` 与 `interval="86400"` 等价）

## 必要参数

| 参数 | 说明 |
|------|------|
| `target` | 目标格式：`clash` / `clashr` / `surge` / `surfboard` / `mellow` / `quan` / `quanx` / `loon` / `singbox` / `ss` / `sssub` / `ssr` / `ssd` / `v2ray` / `trojan` / `mixed`（Shadowrocket 可用 `mixed`）/ `auto`（按 User-Agent 自动判断） |
| `url` | 订阅链接或单节点分享链接（URL 编码，`\|` 分隔多条）。支持 http(s) 订阅、各协议分享链接、本地文件路径（需授权） |

## 目标细分

| 参数 | 说明 |
|------|------|
| `ver` | Surge 版本（如 `target=surge&ver=4`），默认 3 |
| `flavor` | Clash 内核流派：`mihomo`（默认，全特性）/ `premium` / `stash`。按流派自动剔除该内核无法加载的协议与字段，详见[支持矩阵](Protocols-and-Targets.md) |
| `new_name` | Clash 输出使用新字段名（`proxies` 而非 `Proxy`），默认按服务端配置 |

## 节点筛选与处理

| 参数 | 说明 |
|------|------|
| `include` | 只保留备注匹配此正则的节点（也支持 `!!TYPE=` 等[筛选语法](Advanced-Usage.md#节点筛选语法)） |
| `exclude` | 排除备注匹配此正则的节点 |
| `rename` | 重命名规则，格式 `原文@替换`，多条用 `` ` `` 分隔（URL 编码） |
| `emoji` | `true` = 先移除旧 Emoji 再按规则添加（等价 `remove_emoji=true&add_emoji=true`） |
| `add_emoji` / `remove_emoji` | 单独控制添加 / 移除 Emoji |
| `append_type` | 在节点名前加 `[SS]`、`[VMess]` 等类型标记 |
| `sort` | 按节点名排序 |
| `fdn` | 过滤目标客户端不支持的节点（filter deprecated nodes） |
| `list` | 仅输出节点列表：Clash 输出 `proxies:` 片段、Surge/Loon 输出节点行、`quan`/`quanx` 输出可导入的节点 URI |
| `insert` | 是否插入服务端配置的 `insert_url` 节点（默认按服务端配置） |
| `prepend` | 插入节点放在最前（默认按服务端配置） |

## 节点属性覆写

| 参数 | 说明 |
|------|------|
| `udp` | 强制设置 UDP 开关（不带则保留节点原设置） |
| `tfo` | 强制设置 TCP Fast Open |
| `scv` | 强制设置跳过证书校验（skip-cert-verify） |
| `tls13` | 强制设置 TLS 1.3 |

## 配置组装

| 参数 | 说明 |
|------|------|
| `config` | [外部配置](Advanced-Usage.md#外部配置)地址（URL 编码），控制分组与规则 |
| `group` | 自定义组名（写入 SSD/部分格式的组字段） |
| `groups` | 内联自定义分组内容（URL 编码，`@` 换行） |
| `ruleset` | 内联规则集内容（URL 编码，`@` 换行） |
| `expand` | `true` 时把规则集展开为完整规则写入配置；`false` 保留 `RULE-SET` 引用 |
| `classic` | Clash 使用 classical 类型规则集 |
| `interval` | 写入托管配置注释的更新间隔（秒），如 `86400` |
| `strict` | 托管配置是否要求客户端严格按间隔更新 |
| `filename` | 下载文件名（`Content-Disposition`） |
| `dev_id` | QuantumultX 设备 ID，用于生成远程脚本签名 |

## 上传与鉴权

| 参数 | 说明 |
|------|------|
| `token` | API 模式（`api_mode=true`）下的访问令牌；与 `api_access_token` 匹配才被授权（读取本地文件、使用受限功能） |
| `upload` | 转换结果上传到服务端配置的 Gist |
| `upload_path` | 上传路径/文件名 |

## 需要 js-runtime 构建的参数

| 参数 | 说明 |
|------|------|
| `filter` | JS 节点过滤脚本 |
| `sort_script` | JS 排序脚本 |
| `script` | Clash Script 模式（**尚未实现**，参数保留） |

## 其他接口

| 接口 | 说明 |
|------|------|
| `GET /surge2clash?url=<Surge 配置地址>` | Surge 配置直接转 Clash 节点列表（等价 `target=clash&list=true`） |
| `GET /<target>?url=...` | 快捷方式：路径即目标格式，如 `/clash?url=...` 等价 `/sub?target=clash&url=...`，其余参数相同 |

## 示例

```bash
# 转成 mihomo 配置，带 Emoji、开启 UDP、外部配置
curl "http://127.0.0.1:25500/sub?target=clash&url=https%3A%2F%2Fexample.com%2Fsub&emoji=true&udp=true&config=https%3A%2F%2Fexample.com%2Fexternal.ini"

# 转成 Clash Premium 可用的配置（自动剔除 vless/hysteria 等 Premium 不支持的节点）
curl "http://127.0.0.1:25500/sub?target=clash&flavor=premium&url=..."

# 合并两条订阅并只保留香港节点
curl "http://127.0.0.1:25500/sub?target=singbox&url=<sub1>%7C<sub2>&include=%E9%A6%99%E6%B8%AF%7CHK"

# 单条 tuic 分享链接转 Clash 节点列表
curl "http://127.0.0.1:25500/sub?target=clash&list=true&url=tuic%3A%2F%2Fuuid%3Apass%40host%3A443%23name"
```
