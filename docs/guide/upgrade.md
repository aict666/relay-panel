# 安全升级与回滚

升级可以有计划地短暂中断，但不应因为版本不匹配、端口未放行或缺少验证而造成长时间断网。

## 升级前检查

```bash
cd /opt/relay-panel
docker compose ps
docker compose logs --tail=100 panel
```

确认所有关键规则当前可用，并记录：

- 面板和所有节点的当前版本。
- 关键规则的入口端口、协议和 hop 链。
- `.env` 中与转发有关的开关。
- 设备组端口池及云安全组/防火墙开放范围。

备份 `.env` 和数据库。SQLite 不能只在高写入时随意复制；优先停写或使用 SQLite/PostgreSQL 对应的一致性备份方式。

## 常规升级

面板：

```bash
cd /opt/relay-panel
git pull --quiet
./deploy.sh
```

节点：进入面板 **设备分组 → 复制对接命令**，在每台节点重新执行。也可以在节点状态页使用受支持的一键升级。

## 涉及协议 v7 的滚动升级

UOT 和 TCP 0-RTT 配置使用协议版本 7。混合版本期间建议先关闭两个入口开关：

```ini
RELAY_ENABLE_UOT=false
RELAY_ENABLE_TCP_0RTT=false
```

推荐顺序：

1. 写入两个 `false` 后升级面板。
2. 逐台升级所有 relay-node。
3. 至少等待两个配置轮询周期，确认节点报告 `config_protocol_version=7`，且没有 listener error。
4. 保持开关关闭，验证原生 TCP/UDP 规则和端口池。
5. 先在低风险规则上启用 `RELAY_ENABLE_TCP_0RTT=true`，重启面板并测试 TCP。
6. 再启用 `RELAY_ENABLE_UOT=true`，重启面板并测试 UDP 实流量。

TFO 不支持时应回退普通 TCP；UOT 切换会重建 UDP 会话映射，切换瞬间可能丢失单个 datagram。详细行为见[高级路由、UOT 与 0-RTT](/ADVANCED-ROUTING-UOT#升级与回滚顺序)。

## 升级后验收

不要只看容器或 systemd 为绿色。至少验证：

```bash
cd /opt/relay-panel
docker compose ps
docker compose logs --tail=200 panel

systemctl is-active relay-node
journalctl -u relay-node -n 200 --no-pager
```

- 所有节点重新在线，版本符合预期。
- 节点没有协议版本、listener、端口占用或 UOT 认证错误。
- 每类关键规则都跑一次真实 TCP/UDP 双向流量。
- 多跳每个 hop 可达，目标选择与故障转移符合预期。
- 面板流量、连接数和容量指标持续更新。

## 快速回滚

如果问题只与新数据路径有关，先关闭对应入口开关并重启面板：

```ini
RELAY_ENABLE_UOT=false
RELAY_ENABLE_TCP_0RTT=false
```

这会让入口恢复原生 UDP/普通 TCP 路径。若仍有问题，再回滚面板和节点二进制到同一已知可用版本，并恢复数据库/配置备份。

回滚后仍要重复升级后验收。恢复旧进程但不测试实际流量，不算完成回滚。
