# 高级路由、健康探测、UOT 与 TCP 0-RTT

## 目标选择

规则支持六种策略：

- `first`：固定首目标。
- `round_robin`：逐连接 / UDP 会话轮询。
- `failover`：按配置顺序故障转移。
- `weighted`：按目标 `weight`（1–100）做确定性的比例分配。
- `least_latency`：按主动探测延迟 EWMA 与失败率惩罚后的评分选择。
- `least_connections`：选择当前活跃 TCP 连接 / UDP 会话最少的目标。

节点每 10 秒主动探测目标。TCP 规则以及 UOT 入口/中继的下一跳使用真实
TCP 建连；原生 UDP 目标（包括 UOT 出口后的最终 UDP 目标）无法在不知道
上层协议的情况下验证应答，因此执行强制 DNS 解析探测。新会话使用刷新的
DNS 地址。连续 3 次失败，或累计至少 5 次探测/建连尝试且失败率达到 80%，
目标自动熔断 30 秒；全部目标熔断时会 fail-open 再尝试，避免永久锁死。

## UOT：UDP 的 warm-tunnel 0-RTT

`udp` 以及 `tcp_udp` 多跳链中的 UDP 分量都支持认证 UOT：

```text
客户端 UDP -> 入口 UDP/UOT client -> 中间 UOT relay -> 出口 UOT/UDP -> 目标
```

UOT 使用持久 TCP 连接复用多个 UDP 会话并保留 datagram 边界。每条 hop 链路
使用面板派生的 256-bit token 作为 HMAC-SHA256 密钥；服务端每次建连生成随机
nonce，双方做挑战应答，静态 token 不在网络上传输。token 绑定规则、hop 位置
和相邻设备组，配置中也不会下发可用于登录面板的设备组 token。UOT 只负责
链路认证、复用和封包，不额外加密 payload；需要保密时仍应使用 WireGuard、
QUIC、Shadowsocks 等端到端加密协议。

后续 hop 的 UOT 使用面板从该组端口池分配并持久化的独立 TCP 隧道端口。
因此 `tcp_udp` 的原始 TCP 可以继续占用原 hop 端口，UOT 不需要猜测同一
TCP socket 中的数据类型。节点防火墙必须允许设备组端口池内的 TCP 入站；
若无法安全分配独立端口，整条 UDP 链保持原生转发，不会半切换。

`zero_rtt=true` 表示节点提前建立并保持 UOT 连接。连接已预热时，新 UDP
会话首包可直接带 session id 发送，无额外应用层握手，即 warm-tunnel
0-RTT。冷启动仍需一次 TCP 建连和 UOT 认证；它不是 QUIC/TLS 可重放的
early data，也不应宣传成 QUIC 0-RTT。

## TCP 0-RTT：Linux TCP Fast Open

`tcp` 和 `tcp_udp` 多跳链中的 TCP 分量支持 best-effort TCP Fast Open
（TFO）。下游 hop 先开启 `TCP_FASTOPEN` 监听，入口显式启用后，节点到下一
hop 的连接开启 `TCP_FASTOPEN_CONNECT`。当客户端内核已有下一 hop 的 TFO
Cookie 时，首段业务数据可随 SYN 发送，省去一个数据等待 RTT。

边界必须说清楚：

- 普通用户客户端到入口节点的 TCP 三次握手仍然存在；本功能优化的是节点
  之间的 hop。入口公共 listener 不开启 TFO，只有下游 hop listener 开启。
- 第一次连接通常尚无 Cookie，不能 0-RTT；后续暖连接才有机会生效。
- 只有已存在客户端首包、且本次选择只有一个目标和一个 DNS 地址时才使用
  TFO；服务端先发 banner、多目标故障转移和多地址 DNS 自动使用普通 TCP，
  避免延迟建连死锁或破坏备用目标重试。
- Linux 内核、sysctl、中间防火墙或对端不支持时，代码自动退回普通 TCP，
  转发不中断，但也没有 0-RTT 收益。
- TFO 首包具备协议层重放风险；业务协议仍应具备幂等/防重放能力。不适合的
  业务可设置 `RELAY_ENABLE_TCP_0RTT=false` 全局退回普通 TCP。
- 可在 Linux 节点检查 `net.ipv4.tcp_fastopen`；常见值 `3` 表示客户端与
  服务端能力都开启。程序仍以每个 socket 的 best-effort 结果为准。

## 升级与回滚顺序

两个入口开关默认都是 `true`，升级完成后会直接启用 UOT 与 TCP Fast Open。
如果需要混合版本滚动升级，可在升级面板前显式设置：

- `RELAY_ENABLE_UOT=false`：入口继续使用原生 UDP；已升级的下游节点先准备
  原生 UDP 和独立端口 UOT listener。
- `RELAY_ENABLE_TCP_0RTT=false`：入口仍按普通 TCP 连接下一 hop；已升级的
  下游节点先准备 TFO listener。

混合版本滚动升级顺序：

1. 先把两个开关设为 `false`，再升级面板。协议不匹配的旧节点继续使用本地
   缓存配置。
2. 逐台升级所有 relay-node，至少等待两个配置轮询周期，确认相关节点报告
   `config_protocol_version=7`，且没有 listener error。
3. 保持两个开关为 `false`，验证所有原生 TCP/UDP 链和独立 UOT 隧道端口均
   可监听；确认设备组端口池的 TCP 防火墙已放行。
4. 先对低风险规则 canary：设置 `RELAY_ENABLE_TCP_0RTT=true`，重启面板并
   验证 TCP；不支持 TFO 的环境应表现为普通 TCP，而不是连接失败。
5. 再设置 `RELAY_ENABLE_UOT=true`，重启面板并验证 UDP 实流量。
6. 回滚时先把对应变量改回 `false` 并重启面板。入口恢复原生路径，下游保留
   准备态 listener，避免再次启用时重新分配端口。

切换 TFO 会热重启入口 TCP accept loop，但已建立的 TCP 转发任务继续排空；
切换 UOT 会热重启入口 UDP listener 并重建 UDP 会话映射，切换瞬间的单个
datagram 仍可能丢失。因此默认开启不代表切换瞬间零丢包；对不中断有要求的
生产环境应主动采用上面的滚动升级开关与 canary 流程。

## 平滑变更与容量

链路编辑会复用未变设备组原来的 hop 端口和 UOT 隧道端口，前端也只在 hop
列表确实变化时提交拓扑字段。TCP 监听任务重载只停止 accept loop，已经
建立的 TCP 连接继续排空；入口 UOT/UDP 重载则会关闭旧 warm tunnel、清空
UDP 会话映射并自动重连。显式“重启规则”会取消活跃 TCP 连接。

节点状态额外上报：

- `capacity_score`：CPU/内存余量评分（0–100）。
- `predicted_spare_connections`：按当前每连接资源成本估算的剩余连接数。
- `anomaly_detected`：流量、连接数相对节点自身 EWMA 基线异常突增，或
  CPU/内存达到 95% 时置为 true。

这些指标用于运维和调度决策；目标侧自动熔断仍以节点本地的真实探测结果
为准，不让控制面进入每个连接的热路径。
