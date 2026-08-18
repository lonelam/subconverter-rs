# 进阶用法

## 外部配置

`&config=` 指向一份外部配置（ini/yaml/toml，URL 编码），用来定义**分组和规则**，与 C++ 版格式兼容。典型 ini 片段：

```ini
[custom]
; 自定义分组：名称`类型`节点筛选`[测速地址`间隔]
custom_proxy_group=🚀 节点选择`select`.*
custom_proxy_group=♻️ 自动选择`url-test`.*`http://www.gstatic.com/generate_204`300
custom_proxy_group=🇭🇰 香港`url-test`(港|HK|Hong Kong)`http://www.gstatic.com/generate_204`300

; 规则集：分组名,规则来源（URL / 本地路径 / []内联规则）
ruleset=🚀 节点选择,https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/GlobalMedia.list
ruleset=DIRECT,[]GEOIP,CN
ruleset=🚀 节点选择,[]FINAL

enable_rule_generator=true
overwrite_original_rules=true
```

社区维护的大量现成外部配置（如 ACL4SSR 系列）可以直接拿来用。

## 节点筛选语法

`include=` / `exclude=`、分组的节点筛选段，除普通**备注正则**外还支持 `!!` 前缀的属性匹配：

| 语法 | 匹配对象 |
|------|----------|
| `!!GROUP=<正则>` | 节点所属订阅分组名 |
| `!!GROUPID=<范围>` / `!!INSERT=<范围>` | 订阅序号（`0`、`1-3`、`!2` 取反、逗号分隔多段） |
| `!!TYPE=<正则>` | 协议类型：`SS`/`SSR`/`VMESS`/`TROJAN`/`VLESS`/`HYSTERIA`/`HYSTERIA2`/`TUIC`/`ANYTLS`/`SNELL`/`WIREGUARD`/`HTTP`/`SOCKS5` |
| `!!PORT=<范围>` | 端口，如 `!!PORT=443`、`!!PORT=8000-9000` |
| `!!SERVER=<正则>` | 服务器地址 |
| `!!PROTOCOL=<正则>` | SSR 协议 / Hysteria 传输协议 |
| `!!UDPSUPPORT=<yes\|no\|undefined>` | UDP 支持状态 |
| `!!SECURITY=<TLS,TLS13,INSECURE,NONE>` | TLS 安全特征（逗号分隔 = 任一命中） |
| `!!REMARKS=<正则>` | 备注（与直接写正则等价） |

规则可以用 `!!` 级联，前面的属性条件都命中后，剩余部分继续作为筛选：

```
!!TYPE=VMESS!!PORT=443        # 443 端口的 VMess 节点
!!GROUP=机场A!!(港|HK)        # 机场A 中备注含 港/HK 的节点
```

分组定义里的 `[]DIRECT`、`[]REJECT`、`[]节点名` 表示按字面量插入固定项。

## 重命名与 Emoji

- `rename=原文@替换`，多条用 `` ` `` 分隔；`原文` 是正则，同样支持 `!!` 属性前缀
- Emoji 规则在服务端配置（`emojis` 段）：`匹配正则,Emoji`，`emoji=true` 时先移除已有 Emoji 再按规则添加
- 纯 Emoji 名称的节点在移除 Emoji 时会保留原名，避免产生空节点名

## 定时任务（cron）

服务端配置的 `tasks` 段（YAML 示例）：

```yaml
tasks:
  - name: refresh-rules
    cronexp: "0 */6 * * *"
    path: /refreshrules
    timeout: 30
```

按 cron 表达式定时触发内部接口，用于定期刷新规则/配置缓存。

## Web GUI 与短链接

`www/` 是随项目提供的 Next.js 前端（在线服务即此界面），核心页面：

| 页面 | 功能 |
|------|------|
| `/` | 简单转换：订阅 + 目标格式 → 订阅链接 / 短链接 |
| `/convert` | 高级转换器：全部 API 参数可视化配置（含 Clash 内核流派选择） |
| `/links` | 短链接管理：创建、编辑、迁移 |
| `/config` | 在线编辑服务端配置（Monaco 编辑器） |
| `/settings` | 服务设置 |

短链接（`/api/s/<id>`）把冗长的转换 URL 收敛成固定短址，参数改动后短址不变，客户端无需重新扫码/粘贴。数据存储在 Netlify Blobs / Vercel KV。

## 模板系统

`base/` 下的基础配置模板用 [minijinja](https://github.com/mitsuhiko/minijinja)（Jinja2 语法）渲染。模板上下文提供 `request`（请求参数）、`global`（服务端配置的模板变量）、`local`、`node_list` 四个变量，并内置 `url_encode`/`url_decode`/`replace`/`find` 过滤器与 `getLink`/`startsWith`/`endsWith`/`bool`/`default` 等函数，同一模板可按请求参数渲染出不同配置。模板变量在服务端配置的 `template` 段声明。
