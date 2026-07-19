# 故障排查

先按“控制面 → 节点 → 监听端口 → 下一跳 → 最终目标”的顺序定位，避免同时修改多处配置。

## 收集基础信息

面板服务器：

```bash
cd /opt/relay-panel
docker compose ps
docker compose logs --tail=200 panel
```

节点服务器：

```bash
systemctl status relay-node --no-pager
journalctl -u relay-node -n 200 --no-pager
ss -tulnp
```

记录规则 ID、协议、入口端口、hop 顺序、目标地址和问题发生时间。贴日志到公开位置前删除 token、域名/IP 等私人信息。

## 节点离线或反复上下线

1. 检查 `systemctl is-active relay-node`。
2. 检查 `/opt/relay-node/start.sh` 中的 `PANEL_URL` 是否可从节点访问。
3. 在节点上请求面板健康地址，排除 DNS、TLS 和防火墙问题。
4. 确认设备分组 token 未重新生成或粘贴错误。
5. 检查系统时间；严重偏差会造成 TLS 或认证异常。

WebSocket 不通但 HTTP 正常时，现有规则通常继续转发，配置会通过轮询延迟生效。修复反代的 WebSocket upgrade 配置即可。

## 端口没有监听

```bash
ss -tulnp | grep ':你的端口'
journalctl -u relay-node --since '10 minutes ago' --no-pager
```

常见原因：

- 端口已被其他进程占用。
- 端口不在设备组端口池内，或池中没有足够端口分配多跳/UOT。
- 规则未启动、用户无线路授权或套餐已失效。
- 节点仍在使用旧协议配置。

监听 backlog 中看到 `Send-Q 4096` 表示该 socket 请求的监听队列上限；最终有效值仍受 Linux `net.core.somaxconn` 等内核参数限制。它不是当前待发送数据量，也不代表发生拥塞。

## TCP 能连接但很快断开

- 从节点直接连接最终目标，确认目标服务正常。
- 检查目标是否服务端先发 banner；这类协议会自动避免不安全的 TFO 首包路径。
- 多目标规则临时改为固定单目标，逐个排除。
- 查看是否有目标熔断、DNS 解析或 keepalive 回收日志。
- 临时设置 `RELAY_ENABLE_TCP_0RTT=false` 并重启面板，验证是否与 TFO 环境兼容有关。

TFO 关闭后仍失败，通常不是 0-RTT 导致，应继续检查下一跳和目标。

## UDP 无流量或多跳失败

- 使用真实业务协议测试，UDP 发送成功不代表目标已应答。
- 检查云安全组和主机防火墙是否同时放行所需 UDP 与 UOT TCP 端口。
- `tcp_udp` 多跳的 UDP 分量也使用独立 UOT TCP 隧道端口。
- 查看日志中的 UOT listener、认证、warm tunnel 重连信息。
- 临时设置 `RELAY_ENABLE_UOT=false` 并重启面板，验证原生 UDP 路径。

如果原生 UDP 可用而 UOT 不可用，优先检查设备组端口池容量和 hop 间 TCP 入站，而不是修改最终目标。

## 最小延迟策略效果异常

- 等待至少两个主动探测周期再观察选择结果。
- 原生 UDP 探测不能验证业务层响应，延迟评分不等同于真实 UDP 业务质量。
- 检查目标 DNS 是否解析到多个地址、各节点解析结果是否一致。
- 查看目标是否因失败率进入 30 秒熔断。

## 仍无法定位

将规则简化为“单入口 → 单目标、固定首目标、无多跳”，验证后逐项恢复：多目标、负载策略、hop、TFO、UOT。每次只增加一个变量，就能确定具体故障边界。

提交 Issue 时请附：版本、架构、脱敏后的规则结构、最小复现步骤和相关时间段日志；不要附节点 token、`.env` 或完整数据库。
