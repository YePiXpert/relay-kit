# Relay Kit

自己的转发、节点和 BBR 管理工具。面向 **Debian 11+ / Ubuntu 22.04+、systemd、x86_64 / aarch64**。

安装、菜单、配置生成、服务管理和回退代码独立编写。不会下载或执行 arloor、realm-xwPF、mozisen 等第三方管理脚本。转发/代理运行时仍使用系统 nftables，以及固定版本的官方 Realm、Xray、sing-box、Snell 二进制，下载时校验 SHA-256。

## 一键安装

在服务器上执行，安装后输入 `relay` 打开菜单：

```bash
curl -fsSL https://raw.githubusercontent.com/YePiXpert/relay-kit/main/install.sh -o relay-install.sh && sudo bash relay-install.sh && sudo relay
```

root 用户可省略 `sudo`。使用 wget 也可以：

```bash
wget -O relay-install.sh https://raw.githubusercontent.com/YePiXpert/relay-kit/main/install.sh && sudo bash relay-install.sh && sudo relay
```

安装器只下载本仓库 **v0.2.0** 标签的三个源文件，并核对内置 SHA-256。运行核心在选择相应功能时安装。离线查看代码或本地安装：下载完整仓库后执行 `sudo bash forward.sh --install`，不要只下载 forward.sh。

## 菜单

```text
1) nftables 转发
2) Realm 转发
3) 搭建/管理节点
4) BBR
0) 退出
```

不包含订阅服务、流量计费、多用户管理、分流、链式代理或 TG 机器人。

## 转发

同一台服务器选择 nftables 或 Realm 作为转发引擎，支持多条规则、TCP、UDP、修改、删除和启停。节点模块可同时运行，入口端口不能冲突。

```bash
sudo relay init nft
sudo relay add hk1 both 20000 203.0.113.10 30000
sudo relay list
sudo relay set hk1 tcp 20000 203.0.113.20 443
sudo relay disable hk1
sudo relay enable hk1
sudo relay del hk1
sudo relay status
sudo relay logs nft
```

上面的文档地址须换成真实目标地址。`relay init realm` 可切换到 Realm；切换会短暂中断转发，保留规则，并验证新引擎能否接受配置。

- nftables：IPv4 DNAT + masquerade；只管理 `table ip relay_kit`。入口是到本机地址的入站流量，不转发本机 OUTPUT 流量。
- Realm：入口 IPv4，目标支持 IPv4、IPv6、域名；按规则使用核心原生 TCP/UDP 配置。
- 不清空系统防火墙，不调整其他 filter/FORWARD 策略。云安全组、本机防火墙仍需允许相应流量。
- 拒绝占用 SSH 端口、程序正在监听的端口及本工具其他模块占用的端口。
- 配置校验后应用；失败时尝试恢复上一份配置，失败详情会明确显示。已有连接可能因服务重启中断。

## 节点

菜单有 17 种协议/模式，每个节点对应一个独立 systemd 服务和一组随机凭据。

| 命令中的协议名 | 节点 | 核心 | 证书 |
| --- | --- | --- | --- |
| reality | VLESS + REALITY | Xray | 不需要，填写目标网站 SNI |
| reality-xhttp | VLESS + REALITY + XHTTP | Xray | 同上 |
| vless-encryption | VLESS Encryption | Xray | 不需要 |
| vless-ws | VLESS + WS + TLS | Xray | 需要 |
| vmess-ws | VMess + WS | Xray | 可选 --tls |
| vless-vision | VLESS + XTLS Vision | Xray | 需要 |
| trojan | Trojan | Xray | 需要 |
| hysteria2 | Hysteria2 | sing-box | 需要 |
| ss2022 | Shadowsocks 2022 / AES-128-GCM | Xray | 不需要 |
| shadowsocks | 传统 Shadowsocks AEAD | Xray | 不需要 |
| socks5 | SOCKS5 密码认证 | Xray | 不需要 |
| snell4 / snell5 / snell6 | Snell v4 / v5 / v6 | 官方 Snell | 不需要 |
| anytls | AnyTLS | sing-box | 需要 |
| tuic | TUIC v5 | sing-box | 需要 |
| naive | NaiveProxy | sing-box | 需要，分享地址须与证书域名相同 |

```bash
# 将示例 IP、域名和端口替换为你的参数
sudo relay node add reality hk 443 203.0.113.10 --sni your-target.example
sudo relay node add ss2022 ss1 8388 203.0.113.10
sudo relay node add snell6 surge1 6160 203.0.113.10
sudo relay node list
sudo relay node link hk
sudo relay node set hk --port 8443
sudo relay node set hk --rotate
sudo relay node disable hk
sudo relay node enable hk
sudo relay node status hk
sudo relay node logs hk
sudo relay node del hk
```

`--rotate` 更换凭据后需要重新导入连接信息。Snell 导出 Surge 配置行，其余导出对应连接链接。默认监听 `0.0.0.0`；IPv6 入口可用 `--bind ::`，客户端和系统需支持 IPv6。

TLS 节点使用现有证书：

```bash
sudo relay node add hysteria2 hy1 8443 node.example.com \
  --sni node.example.com \
  --cert /etc/letsencrypt/live/node.example.com/fullchain.pem \
  --key /etc/letsencrypt/live/node.example.com/privkey.pem
```

也可在菜单申请 Let's Encrypt，或执行 `sudo relay cert node.example.com your@email.example`。该功能通过系统仓库安装 Certbot，使用 HTTP-01 并接受 Let's Encrypt 服务条款；域名应指向服务器，TCP/80 必须空闲且公网可达。安装续期部署钩子，成功续期后重新应用节点配置。

其他参数：

- WS/XHTTP：`--path /your-path`。
- Vision/Trojan：`--fallback 8080`，将未通过代理认证的连接回落至本机服务。
- Shadowsocks：`--method aes-128-gcm|aes-256-gcm|chacha20-poly1305`。
- Snell v4/v5：`--obfs http`；Snell v6：`--mode default|unshaped`；Snell：`--dns 1.1.1.1,8.8.8.8`。
- Hysteria2：可选 `--up-mbps 100 --down-mbps 100`。
- 高级参数也可通过 `relay node set 名称 ...` 修改。

Hysteria2/TUIC 入口使用 UDP；SS 两种模式、Snell v5 和 Naive 支持 UDP 入口；其余主要入口为 TCP。SOCKS5 的 UDP ASSOCIATE 按请求创建 UDP 套接字，若使用该功能须配置相应防火墙策略。SOCKS5 本身不加密传输。

## BBR

```bash
sudo relay bbr status
sudo relay bbr on
sudo relay bbr off
```

`on` 设置 fq + bbr，并保存原值；`off` 恢复保存的原值。只使用现有内核能力，内核不支持时返回错误，不替换内核。BBR 是系统 TCP 拥塞控制设置，对 QUIC 协议自带的拥塞控制不生效。

## 文件和运行依赖

- 管理入口：`/usr/local/bin/relay`。
- 管理代码及核心：`/usr/local/lib/relay-kit/`。
- 转发状态：`/etc/relay-kit/forward.json`。
- 节点状态：`/etc/relay-kit/nodes.json`；私钥和凭据文件权限 600。
- 节点服务：`relay-node-节点名称.service`；使用 DynamicUser 和 systemd LoadCredential。
- 转发服务：`relay-kit-nft.service` / `relay-kit-realm.service`。
- BBR：`/etc/sysctl.d/99-relay-kit-bbr.conf`。
- 最近一次状态备份：对应的 `.json.bak` 文件。

运行核心固定为 Realm 2.9.6、Xray 26.10.29、sing-box 1.14.4、Snell 4.1.1 / 5.0.1 / 6.0.0。校验值和官方下载地址均在源码中，可直接审阅。SHA-256 用于确认下载内容符合固定版本，并不等于对核心实现做过完整安全审计。各运行组件保留各自许可证；本仓库管理代码采用 MIT。

从旧 0.1.0 更新会替换 Relay Kit 管理入口，不会删除此前由其他工具安装的 nat/xwPF 服务，也不会自动迁移其规则。请先停用冲突的旧服务，再添加本工具的规则。

## 验证

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
sudo unshare --mount bash tests/test-install.sh
python3 tests/fetch-cores.py
sudo unshare --mount --net --pid --fork bash tests/run-network.sh
sudo python3 tests/test-systemd.py
```

自动测试覆盖输入和下载校验、端口冲突、失败回退、BBR 恢复、安装保护、真实 nftables/Realm TCP 和 UDP 收发，以及 17 种节点模式的官方核心配置和代理连接。网络测试在独立命名空间中运行，不改变主机网络。systemd 测试使用临时服务和私有网络，结束后清理。当前实测环境为 Ubuntu 24.04 x86_64；ARM64 下载校验值已固定，但未在 ARM64 硬件上运行测试。
