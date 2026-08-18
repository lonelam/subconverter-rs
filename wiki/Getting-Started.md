# 快速开始

## 方式一：在线服务（零部署）

打开 <https://subconverter-rs.netlify.app>：

- **首页**：粘贴订阅链接、选目标格式，直接得到转换后的订阅地址（可一键生成短链接）
- **/convert**：高级转换器，暴露全部 API 参数（过滤、重命名、Emoji、外部配置、Clash 内核流派等）

生成的链接填进 Clash/mihomo、Surge、sing-box 等客户端的"订阅地址"即可，客户端会按更新间隔自动重新拉取。

> 注意：在线服务会经手你的订阅链接。对隐私敏感请自托管（见下文）。

## 方式二：下载预编译二进制

在 [Releases](https://github.com/lonelam/subconverter-rs/releases) 下载对应平台的压缩包：

| 文件 | 平台 |
|------|------|
| `subconverter-linux-amd64-*.tar.gz` | Linux x86_64（musl 静态链接） |
| `subconverter-linux-aarch64-*.tar.gz` | Linux ARM64 |
| `subconverter-linux-armv7-*.tar.gz` / `-x86` | 树莓派等 ARMv7 / 32 位 x86 |
| `subconverter-macos-aarch64-*.tar.gz` | macOS Apple Silicon |
| `subconverter-macos-x86_64-*.tar.gz` | macOS Intel |

Windows 暂无预编译包，请用源码构建、WSL 或 Docker。

解压后运行：

```bash
tar xzf subconverter-linux-amd64-*.tar.gz
cd subconverter
./subconverter          # 服务器起在 127.0.0.1:25500
```

验证：

```
curl "http://127.0.0.1:25500/sub?target=clash&url=<URL 编码后的订阅链接>"
```

## 方式三：Docker

镜像随 Release 发布到 GitHub Container Registry（附架构后缀）：

```bash
docker run -d --name subconverter -p 25500:25500 \
  ghcr.io/lonelam/subconverter-rs:<版本标签>-amd64
# ARM64 主机使用 -arm64 后缀的标签
```

镜像内工作目录为 `/app`（含 `base/` 运行时数据），暴露端口 `25500`。挂载自定义配置：

```bash
docker run -d -p 25500:25500 \
  -v $(pwd)/pref.yml:/app/pref.yml \
  ghcr.io/lonelam/subconverter-rs:<版本标签>-amd64
```

## 方式四：源码构建

需要 Rust 工具链（stable）：

```bash
git clone https://github.com/lonelam/subconverter-rs.git
cd subconverter-rs
cargo build --release --features web-api          # 二进制必须启用 web-api 特性
# 可选：JS 脚本支持（filter=/sort_script= 参数）
cargo build --release --features web-api,js-runtime
./target/release/subconverter
```

注意：服务器从**当前工作目录**读取 `base/` 里的模板、规则和配置，请在仓库根目录（或把 `base/` 内容复制到工作目录后）运行。

## 命令行一次性转换（无需起服务器）

`--url` 接收一个与 HTTP API 相同的请求 URI，内部走同一套处理逻辑：

```bash
./subconverter --url "/sub?target=clash&url=<URL 编码后的订阅>&emoji=true" -o config.yaml
```

适合放进 cron / CI 定期生成配置文件。全部参数见 [HTTP API 参数详解](HTTP-API.md)。

## 服务器配置

启动参数：

| 参数 | 说明 |
|------|------|
| `-c, --config <FILE>` | 指定配置文件路径 |
| `-a, --address <ADDRESS>` | 监听地址（覆盖配置文件） |
| `-p, --port <PORT>` | 监听端口（覆盖配置文件） |
| `--url <URL>` + `-o <FILE>` | 一次性转换模式（见上） |

配置文件按 `pref.toml` → `pref.yml` → `pref.ini` 的优先级加载（首个存在者生效），`base/` 目录内附带三种格式的 `pref.example.*` 模板。常用配置项：

- `api_mode` / `api_access_token`：API 模式下，携带正确 `token=` 的请求才被授权（授权决定能否读本地文件、使用 `insert_url` 本地路径等）
- `default_url` / `insert_url`：无 `url=` 参数时的默认订阅、自动插入的节点源
- `exclude_remarks` / `include_remarks`、`rename_node`、Emoji 规则
- `proxy_config` / `proxy_ruleset` / `proxy_subscription`：拉取外部资源时使用的代理
- 缓存时长、最大规则数等服务端限制
- `tasks`：cron 定时任务（YAML 配置中留空的 `tasks:` 键会被当作无任务，不再报错）
