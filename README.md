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

安装器只下载本仓库 **v0.3.1** 标签的四个源文件（forward.sh、relay.py、nodes.py、menu.py），并核对内置 SHA-256。运行核心在选择相应功能时安装。离线查看代码或本地安装：下载完整仓库后执行 `sudo bash forward.sh --install`，不要只下载 forward.sh。

服务器直连 GitHub 失败时，安装器和核心下载会依次改用镜像 `ghfast.top`、`gh-proxy.com`。镜像下载的内容同样要通过内置 SHA-256 校验，不符就丢弃。`RELAY_KIT_MIRRORS` 可以指定镜像前缀（空格或逗号分隔），设为空则只直连。连安装器本身都下载不了时（如 Po0），可以经镜像取安装器：

```bash
curl -fsSL https://ghfast.top/https://raw.githubusercontent.com/YePiXpert/relay-kit/main/install.sh -o relay-install.sh && sudo bash relay-install.sh && sudo relay
```

这样取到的安装器本身没有经过校验，等于信任该镜像。介意的话，在本地下载完整仓库，核对后上传安装。

## 菜单

```text
══════════════════════════════════════════════════════════
  Relay Kit v0.3.1  │  转发 · 节点 · BBR
  快捷命令 relay · 命令行用法 relay -h
══════════════════════════════════════════════════════════
  系统  Debian GNU/Linux 12 (bookworm) · 6.1.0-28-amd64 · x86_64
  转发  ● 运行中 · nftables · 2 条规则
  节点  ● 2/2 运行中
  BBR   ● 已启用（bbr + fq）
──────────────────────────────────────────────────────────
   1) nftables 转发       ● 当前引擎
   2) Realm 转发          支持域名 / IPv6 目标
   3) 节点管理            搭建 · 分享链接 · 二维码
   4) BBR 加速
──────────────────────────────────────────────────────────
   5) 核心组件            版本 · 离线导入
   6) 卸载 Relay Kit
   0) 退出
──────────────────────────────────────────────────────────
  请选择 [0-5]:
```

- 首页显示系统、转发引擎、节点运行数和 BBR 状态；子菜单顶部列出现有规则或节点及运行状态。
- 修改、删除、查看时从列表选择规则或节点，只有一个时自动选中，不需要手输名称。
- 添加时直接回车即用默认值：随机空闲高位端口、本机公网 IP、随机 REALITY 目标站点、随机 WS/XHTTP 路径、按协议和端口生成的名称。端口被占用、地址格式错误等当场提示重输；手动填写 Po0 等国内入口默认封禁的端口时会先提示确认。
- 节点详情显示全部参数和分享链接；安装 `qrencode` 后同时显示二维码。
- Ctrl+C 取消当前操作；删除节点/规则、切换转发引擎和卸载都需要确认。
- 公网 IP 先取本机出口地址；若是内网地址（NAT 机器），再向 `https://one.one.one.one/cdn-cgi/trace` 查询。检测不到时手动填写。

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

- nftables：IPv4 DNAT + masquerade（源地址自动取出网网卡地址，云主机上就是内网 IP，不用手填）；转发的 TCP 连接把 MSS 限制为 1452；只管理 `table ip relay_kit`。入口是到本机地址的入站流量，不转发本机 OUTPUT 流量。
- `nftables.service` 重启或重载会清空整个规则集，Relay Kit 的规则随后自动重新应用。手动执行 `nft -f /etc/nftables.conf` 这类含 `flush ruleset` 的命令后，运行 `sudo relay apply`。
- Realm：入口 IPv4，目标支持 IPv4、IPv6、域名；按规则使用核心原生 TCP/UDP 配置。
- 不清空系统防火墙，不调整其他 filter/FORWARD 策略。云安全组、本机防火墙仍需允许相应流量。其他表的 forward 链默认丢弃时（Docker、ufw、firewalld 常见），nftables 转发的连接会被丢弃；Relay Kit 会在应用规则和菜单里提示，这时可以改用 Realm，或在对应防火墙里放行。
- 拒绝占用 SSH 端口、程序正在监听的端口、本工具其他模块占用的端口，以及其他 nftables 表（手写规则、其他脚本、Docker 等）已经 DNAT 的端口。
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
sudo relay node add reality hk 24443 203.0.113.10 --sni your-target.example
sudo relay node add ss2022 ss1 8388 203.0.113.10
sudo relay node add snell6 surge1 6160 203.0.113.10
sudo relay node list
sudo relay node info hk    # 参数、分享链接和二维码
sudo relay node link hk
sudo relay node link hk --via 198.51.100.1 --via-port 30001    # 临时生成经中转入口连接的链接
sudo relay node set hk --via 198.51.100.1 --via-port 30001 --via-label 广州    # 保存中转入口
sudo relay node set hk --clear-via
sudo relay node set hk --port 28443
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

## 在 Po0 上使用

按 [Po0 Wiki](https://wiki.uuuz.de/) 的标准链路：`客户端 → Po0 入口机 → 香港/日本出口机`。

1. **出口机**：`relay` → 3) 节点管理 → 1) 添加节点，端口直接回车用随机高位端口。先用客户端直连出口机，确认可用。
2. **出口机**：3) 节点管理 → 3) 中转入口，保存 Po0 公网 IP 和入口端口（可存多个，如广州、华东各一个）。之后节点详情会同时列出直连和经每个入口的分享链接、二维码，并提示 Po0 上要加的转发。命令行：`sudo relay node set 名称 --via Po0公网IP --via-port 入口端口 --via-label 广州`。
3. **Po0**：`relay` → 1) nftables 转发 → 1) 添加规则：入口端口 → 出口机 IP:节点端口。协议按第 2 步的提示选（Hysteria2/TUIC 需要 UDP）。
4. 客户端导入第 2 步的链接测试。

注意：

- 广州/华东 BGP 默认双向封禁 TCP/UDP `80`、`443`、`8080`、`8443`、`8000`、`1080`，Po0 的入口端口和出口机的节点端口都要避开。向导的默认端口不会选到这些端口，手动填写时会提示确认。
- Po0 只做转发，不要在 Po0 上建节点：广州/华东 BGP 禁止用于回国访问。
- Po0 上建议用 nftables 引擎，它只依赖系统软件源；Realm 要从 GitHub 下载。
- Po0 访问 GitHub 受限时，下载会自动改用镜像（见“一键安装”）。镜像也不通时：
  - 用 root 先执行 `export https_proxy=http://用户:密码@代理IP:端口`，再运行安装命令（`sudo` 默认不传递这个变量）；
  - 或者在本地下载官方核心压缩包，上传后用"5) 核心组件 → 1) 导入离线包"，或执行 `sudo relay core import 文件`。
- 之前按 Wiki 手写过 `/etc/nftables.conf` 或用过其他转发脚本的，先备份并删除旧的转发规则。同一端口已被其他 nftables 表转发时，Relay Kit 会拒绝添加并指出是哪张表。如果用 `systemctl disable --now nftables` 停掉旧配置，停止时会清空整个规则集，之后运行 `sudo relay apply` 重新应用。
- BBR 开在出口机上：nftables 转发时 TCP 由客户端和出口机端到端控制，Po0 上的 BBR 对转发流量基本没有作用，用 Realm 时才有效。
- 开了防火墙白名单（鸡险 / po0fw）的，客户端所在的 /24 网段要在白名单里，否则入口端口连不上。

## 核心组件和离线安装

```bash
sudo relay core list                        # 本机架构的固定版本、官方下载地址和 SHA-256
sudo relay core import Xray-linux-64.zip    # 导入上传到服务器的官方压缩包
```

导入时按内置 SHA-256 识别是哪个核心、哪个架构，只接受固定版本的官方压缩包。菜单"5) 核心组件 → 1) 导入离线包"会在当前目录、`/root`、`/tmp` 里自动查找。

## 主机防火墙

添加、修改、删除节点或 Realm 规则后，Relay Kit 检测本机防火墙，并按需放行监听端口：

- ufw 启用时：`ufw allow 端口/协议 comment relay-kit`。
- firewalld 运行时：`firewall-cmd --add-port`（同时写入永久配置）。
- iptables 的 INPUT 链以 REJECT/DROP 收尾时（甲骨文云等镜像常见）：在该规则之前插入带 `relay-kit` 注释的 ACCEPT 规则；装有 `netfilter-persistent` 时一并保存。

只记录 Relay Kit 自己加的规则（`/etc/relay-kit/firewall.json`）。删除节点、改端口和卸载时只撤销这些，你原有的规则不会被删。nftables 转发的流量走 FORWARD，不经过这些放行规则，见"转发"一节的提示。云厂商的安全组仍需自行放行。

## BBR

```bash
sudo relay bbr status
sudo relay bbr on
sudo relay bbr off
```

`on` 设置 fq + bbr，并保存原值；`off` 恢复保存的原值。只使用现有内核能力，内核不支持时返回错误，不替换内核。BBR 是系统 TCP 拥塞控制设置，对 QUIC 协议自带的拥塞控制不生效。

## 卸载

```bash
sudo relay uninstall        # 需输入 yes 确认；加 --yes 跳过确认
```

停止并删除全部转发规则、节点、服务文件、`/etc/relay-kit`、`/usr/local/lib/relay-kit` 和 `relay` 命令；由本工具启用的 BBR 恢复原设置。不属于本工具的同名文件、Let's Encrypt 证书和系统软件包会保留。

## 文件和运行依赖

- 管理入口：`/usr/local/bin/relay`。
- 管理代码及核心：`/usr/local/lib/relay-kit/`。
- 转发状态：`/etc/relay-kit/forward.json`。
- 节点状态：`/etc/relay-kit/nodes.json`；私钥和凭据文件权限 600。
- 节点服务：`relay-node-节点名称.service`；使用 DynamicUser 和 systemd LoadCredential。
- 转发服务：`relay-kit-nft.service` / `relay-kit-realm.service`。
- BBR：`/etc/sysctl.d/99-relay-kit-bbr.conf`。
- 最近一次状态备份：对应的 `.json.bak` 文件。
- 防火墙放行记录：`/etc/relay-kit/firewall.json`。

运行核心固定为 Realm 2.9.6、Xray 26.10.31、sing-box 1.14.4、Snell 4.1.1 / 5.0.1 / 6.0.0。校验值和官方下载地址均在源码中，可直接审阅。SHA-256 用于确认下载内容符合固定版本，并不等于对核心实现做过完整安全审计。各运行组件保留各自许可证；本仓库管理代码采用 MIT。

从 0.2.0 或 0.3.0 更新：重新运行一键安装命令即可，已有的转发规则和节点照常沿用。

- 0.3.1 改为固定 Xray 26.10.31（官方已撤回 26.10.29）。之后第一次修改节点或执行 `sudo relay node apply` 时，会自动下载新版并重启用到它的节点；在那之前节点继续用旧版运行。
- 下一次增删转发规则或执行 `sudo relay apply` 时，`relay-kit-nft.service` 会自动更新：跟随 `nftables.service` 重启，并加上 MSS 钳制。
- 下一次增删节点或执行 `sudo relay node apply` 时，会按需在主机防火墙放行节点端口。
- 节点菜单编号有变化：3 是中转入口，修改、删除移到 4、5。主菜单新增"5) 核心组件"，卸载移到 6。

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
