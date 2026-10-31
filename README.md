# Relay Kit

面向 Debian / Ubuntu 的中文转发管理入口。运行同一个脚本，自己选择 **nftables** 或 **Realm**，适用于 VPS 中转、端口映射和多段转发。

```text
Relay Kit 0.1.0 — 请选择转发方式
1) nftables（arloor）
2) Realm（realm-xwPF）
0) 退出
```

这是独立维护的菜单和安装入口：nftables 管理由 [arloor/nftables-nat-rust](https://github.com/arloor/nftables-nat-rust) 提供，Realm 管理由 [zywe03/realm-xwPF](https://github.com/zywe03/realm-xwPF) 提供。转发能力、上游配置和许可证归各自项目。

## 快速开始

在 Linux 服务器上下载并安装菜单：

```bash
sudo apt-get update
sudo apt-get install -y curl ca-certificates
curl -fL --proto '=https' --proto-redir '=https' \
  https://raw.githubusercontent.com/YePiXpert/relay-kit/main/install.sh \
  -o relay-install.sh
sudo bash relay-install.sh
sudo relay
```

安装菜单只创建 `/usr/local/bin/relay`。进入菜单后选择引擎，再选择安装，不会同时安装两个引擎。

已有源码或 GitHub ZIP 包时，也可以跳过菜单下载：

```bash
sudo bash forward.sh --install
sudo relay
```

不安装快捷命令也能直接运行 `sudo bash forward.sh`。更新菜单可重新运行上面的安装步骤；转发引擎在各自子菜单中更新。

## 命令

| 命令 | 功能 |
| --- | --- |
| `sudo relay` | 选择转发引擎 |
| `sudo relay nft` | 进入 nftables 安装、配置和诊断菜单 |
| `sudo relay realm` | 进入 Realm 安装和管理入口 |
| `relay --version` | 显示版本 |
| `relay --help` | 显示帮助 |

运行菜单不需要联网；下载安装转发后端时需要访问上游 GitHub 和系统软件源。

## 两种转发方式

| 方式 | 提供的能力 | 使用入口 |
| --- | --- | --- |
| nftables | 内核 NAT、TCP/UDP、IPv4/IPv6、域名解析更新、端口段 | 编辑 `/etc/nat.toml`；`nat.service` |
| Realm | 用户态 TCP/UDP、交互式规则管理、负载均衡、导入导出 | 上游中文菜单；`realm.service` |

- nftables 安装走 arloor 的 TOML 配置方式；配置更新通常在 60 秒内被程序检测，无需每次重启。安装脚本中的 GitHub 下载代理前缀会替换为直连 GitHub。
- Realm 使用 realm-xwPF 管理，后续增加规则、删除规则、服务管理等在其菜单中完成。
- 两个引擎各自维护配置。选择另一个菜单不等于迁移已有规则；同一台机器切换同一个入口端口时，先在原管理器中移除冲突规则。
- 此入口不安装 Web 面板。上游提供的隧道、流量统计等扩展功能按需使用。

## 环境要求与影响

- Debian / Ubuntu，Bash，systemd；安装和变更系统配置需要 root。
- 当前 nftables 安装路径只接入 **x86_64**；Realm 架构支持由上游安装器检测。
- 安装器下载上游当前分支及其指定的版本，不是冻结的供应链快照。
- arloor 的 Docker 兼容逻辑可能将 FORWARD 策略调整为 ACCEPT；已有复杂防火墙时，应先了解其对当前策略的影响。参见[上游说明](https://github.com/arloor/nftables-nat-rust#-docker-兼容性)。
- 云安全组和本机防火墙需允许所用端口；转发无法替代后端服务，也不会创建运营商专线。
- `/usr/local/bin/relay` 若已属于其他程序或是符号链接，安装会停止，避免覆盖其他工具。

## 转发配置示例

```text
客户端 → 入口机:20000 → 中转机:30000 → 落地机:40000
```

示例地址来自文档专用地址段，必须换成真实地址。

**中转机选择 Realm**：添加标准转发，监听 `0.0.0.0:30000`，目标 `198.51.100.20:40000`，协议按业务需要选择 TCP、UDP 或 both。先验证此段可用。

**入口机选择 nftables**：编辑 `/etc/nat.toml`，新安装的空配置可替换为：

```toml
[[rules]]
type = "single"
sport = 20000
dport = 30000
domain = "203.0.113.10"
protocol = "all"
ip_version = "ipv4"
comment = "entry to relay"
```

`203.0.113.10` 换成入口机能访问的中转机地址。已有规则时追加 `[[rules]]`；初始空配置中的 `rules = []` 不能与后续 `[[rules]]` 同时保留。

客户端连接入口机的公网 IP 和 `20000` 端口。无需每一段使用相同引擎，也可以只部署单层转发。

## 诊断

```bash
# nftables 后端
sudo systemctl status nat --no-pager
sudo journalctl -u nat -n 50 --no-pager

# Realm 后端
sudo systemctl status realm --no-pager
sudo journalctl -u realm -n 50 --no-pager
```

nftables 规则不表现为 `ss` 中的本地监听进程；Realm 则会创建监听 socket。测试 nftables 入口时使用另一台机器，避免本机测试绕过 PREROUTING。

## 开发与验证

```bash
bash -n forward.sh
bash -n install.sh
shellcheck forward.sh install.sh
python3 -m unittest discover -s tests -p 'test_*.py' -v
sudo unshare --mount bash tests/test-install.sh
```

测试覆盖菜单选择、返回、直接进入引擎、版本帮助、异常参数、输入结束和下载失败时禁止执行。另在隔离挂载空间验证安装、更新、可执行权限及保护其他文件/符号链接。GitHub Actions 运行相同检查，不安装转发后端、不修改防火墙。

当前测试不等同于在真实 VPS 上完成上游安装和整条转发链路验收；请根据实际路由、端口和防火墙进行连接测试。

## 致谢与许可

- [arloor/nftables-nat-rust](https://github.com/arloor/nftables-nat-rust)：nftables 转发管理。
- [zywe03/realm-xwPF](https://github.com/zywe03/realm-xwPF)：Realm 交互式管理。
- [zhboner/realm](https://github.com/zhboner/realm)：Realm 转发程序。

Relay Kit 自有脚本采用 [MIT License](LICENSE)。本仓库不打包上游源码或二进制，上游项目遵循各自许可证。
