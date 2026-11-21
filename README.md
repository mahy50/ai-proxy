# ai-proxy

面向 macOS 的 **免 TUN、一键开启 / 一键撤回** Antigravity (`agy`) 与 Codex 代理工具（**FlClash 保持 100% 默认配置即可**）。

## 架构与目录隔离

程序本体、用户配置、运行态完全解耦，升级与分发不会覆盖个人配置：

| 层级 | 默认路径 | 说明 |
| :--- | :--- | :--- |
| **程序本体** | `/usr/local/bin/ai-proxy` | 单文件 Python `zipapp` 可执行文件（无第三方依赖） |
| **用户配置** | `~/.config/ai-proxy/config.json` | 首次运行自动生成，可通过 `AI_PROXY_CONFIG` 覆盖 |
| **运行态与日志** | `~/Library/Application Support/ai-proxy/` | PID、日志、`.env` 备份、`launchctl.json`，可通过 `AI_PROXY_STATE_DIR` 覆盖 |

## 工作原理

1. **零侵入应用本体，FlClash 保持默认**
   - 不修改 Antigravity / ChatGPT (Codex) 应用本体和代码签名，无需关闭 SIP。
   - 不修改 `/etc/hosts`；FlClash 无需开启 TUN、无需开启「覆盖 DNS」、无需修改 `use-system-hosts`、无需添加覆写脚本。
2. **macOS 原生 `/etc/resolver/` 分域 DNS + 本地 SNI 转发**
   - 后台守护进程同时监听 **UDP DNS 应答器（`127.0.0.1:15353`）** 和 **TLS SNI 转发服务（`:443`）**。
   - 在 `/etc/resolver/` 下写入带 `# managed by ai-proxy` 标记的域名文件（如 `googleapis.com`、`openai.com`、`chatgpt.com` 等），自动覆盖所有泛域名子域。
   - 本机应用经 macOS `mDNSResponder` 命中 `/etc/resolver/` 连到本地 `:443`；中继服务从 TLS `ClientHello` 读取 SNI 域名（不解密流量）直接转交上游 FlClash（默认 `socks5://127.0.0.1:7890`）。因为 FlClash 不读取 `/etc/resolver/`，两者完全解耦、零回环。
3. **Codex 环境托管（`.env` + `launchctl`）**
   - 自动在真实用户的 `~/.codex/.env` 写入带起止注释标记的代理变量（保留原有 `OPENAI_API_KEY` 等配置）。
   - 自动通过 `launchctl setenv` 同步 macOS GUI 会话环境变量，确保从 Dock / Finder 启动的 ChatGPT (Codex) 及内置 CLI 也能直接读取。

## 状态变化与撤回机制

| 项目 | `ai-proxy on` | `ai-proxy off` |
| :--- | :--- | :--- |
| 后台进程 (`_relay`) | 启动本地 `UDP:15353` DNS + `TCP:443` SNI 转发 | `SIGTERM` 停止进程并清理 PID 文件 |
| `/etc/resolver/*` | 写入带 `# managed by ai-proxy` 的托管文件（跳过非托管文件） | 仅删除带 `# managed by ai-proxy` 的文件 |
| `~/.codex/.env` | 写入 `# >>> ai-proxy managed start >>>` 区块 | 移除托管区块（若原本不存在且为空则删除文件） |
| `launchctl` 会话环境 | 设置 `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` | 执行 `unsetenv` 清除所设置的变量 |
| macOS DNS 缓存 | 刷新 `mDNSResponder` 缓存 | 刷新 `mDNSResponder` 缓存 |

## 安装与分发（单文件）

### 一键安装（推荐）

在任意一台 macOS 上执行即可直接从 GitHub Releases 下载校验并安装到 `/usr/local/bin/ai-proxy`：

```zsh
curl -fsSL https://raw.githubusercontent.com/mahy50/ai-proxy/main/scripts/install.sh | bash
```

可选参数（通过 `bash -s --` 传参）：

```zsh
# 安装指定版本或指定安装目录（如无需 sudo 的 ~/.local/bin）
curl -fsSL https://raw.githubusercontent.com/mahy50/ai-proxy/main/scripts/install.sh | bash -s -- --version v1.0.0 --prefix ~/.local/bin

# 若直连 GitHub 较慢，脚本会自动探测本地 127.0.0.1:7890 重试，也可显式指定代理
curl -fsSL https://raw.githubusercontent.com/mahy50/ai-proxy/main/scripts/install.sh | bash -s -- --proxy socks5h://127.0.0.1:7890
```

### 从源码构建并本地安装

```zsh
./scripts/build.sh
sudo install -m 755 dist/ai-proxy /usr/local/bin/ai-proxy
```

构建后会在 `dist/` 下生成：
- `dist/ai-proxy`：跨 Intel / Apple Silicon 通用的单文件可执行程序
- `dist/ai-proxy-v<VERSION>.tar.gz`：发布压缩包
- `dist/SHA256SUMS`：SHA256 校验文件

## 检查更新与升级

`ai-proxy` 内置基于 GitHub Releases + SHA256 校验的自升级能力（会自动复用配置中的 FlClash 上游代理访问 GitHub，失败时回退直连）：

```zsh
# 检查是否有新版本
ai-proxy check-update
# 或
ai-proxy upgrade --check

# 一键升级到最新版本（若代理正在运行，会自动平滑重启）
ai-proxy upgrade

# 安装或回退到指定版本 / 强制重装当前版本
ai-proxy upgrade --version v1.0.0
ai-proxy upgrade --force
```

## 常用命令

```zsh
# 查看版本
ai-proxy --version

# 开启免 TUN 代理（会自动请求 sudo）
ai-proxy on

# 全面检测（验证 AI 规则出口地区、:443 SNI + UDP:15353 DNS、/etc/resolver、Codex 环境及核心接口）
ai-proxy check

# 关闭并彻底撤回（会自动请求 sudo）
ai-proxy off

# 查看状态 / 重启 / 实时日志
ai-proxy status
ai-proxy restart
ai-proxy logs -f

# 查看或修改配置（上游代理地址、服务开关、launchctl 开关）
ai-proxy config
ai-proxy config --proxy socks5://127.0.0.1:7890
ai-proxy config --disable-codex      # 仅代理 Antigravity
ai-proxy config --enable-codex       # 同时代理 Antigravity + Codex
ai-proxy config --disable-agy        # 仅代理 Codex
ai-proxy config --enable-agy

# 按服务管理 /etc/resolver 托管域名区域
ai-proxy domains list
ai-proxy domains add googleusercontent.com --service antigravity
ai-proxy domains add example.com --service codex
ai-proxy domains remove example.com

# 卸载（先停止并清理系统接管状态，删除可执行文件，保留个人配置）
ai-proxy uninstall

# 彻底卸载（额外删除 ~/.config/ai-proxy 与 ~/Library/Application Support/ai-proxy）
ai-proxy uninstall --purge
```

> 提示：若在开启 `ai-proxy on` 之前已经打开了 ChatGPT (Codex) 窗口，建议 `Cmd + Q` 完全退出后从 Dock 重新打开，使其读取最新的会话代理变量。

## 运行测试

```zsh
./scripts/build.sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## 发布新版本（维护者）

推送以 `v` 开头的 tag 后，GitHub Actions（[release.yml](.github/workflows/release.yml)）会在 `macos-latest` 自动构建、运行全部测试并创建 GitHub Release：

1. 同步更新 [VERSION](VERSION) 与 [\_\_init\_\_.py](src/ai_proxy/__init__.py) 中的 `__version__`（保持一致）。
2. 提交修改并打 tag：
   ```zsh
   git add VERSION src/ai_proxy/__init__.py
   git commit -m "chore: release vX.Y.Z"
   git tag -a vX.Y.Z -m "Release vX.Y.Z"
   git push origin main --follow-tags
   ```
