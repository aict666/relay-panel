# 安全配置

RelayPanel 会控制公网监听端口和转发节点，建议把下面项目作为上线前的最低要求。

## 管理员账号

- 首次登录立即把 `admin123` 改为唯一的强密码。
- 不要复用服务器 SSH、邮箱或其他面板密码。
- 只把管理员权限授予确实需要的人；普通使用者使用普通账号和套餐授权。

## HTTPS 与反向代理

公网面板应使用 HTTPS。推荐在面板前使用 Caddy、Nginx 或其他反向代理，并确保 WebSocket 升级头正确传递。完整示例见[反向代理](/REVERSE-PROXY)和[简化 TLS 部署](/TLS-SIMPLE)。

反代后至少验证：

```bash
curl -I https://你的面板域名/
```

然后登录面板，确认节点日志出现 `websocket connected`。WebSocket 不通时 HTTP 轮询仍可工作，但配置更新会延迟。

## 防火墙最小开放

- 面板：只开放 HTTP/HTTPS 对外端口，数据库端口不要暴露公网。
- 节点：只开放实际使用的入口端口和设备组端口池。
- SSH：限制来源地址或使用 VPN/堡垒机，禁用密码登录更稳妥。
- 多跳：尽量只允许上一跳节点访问下一跳端口池。

`tcp_udp` 的 UDP 多跳使用 UOT 时会额外占用端口池内的 TCP 端口。只开放原始 UDP 端口会导致 UOT 隧道失败。

## Token 保护与轮换

设备分组 token 等同于节点接入凭据：

- 不要提交到 Git 仓库、公开日志、Issue 或截图。
- 节点上的 `/opt/relay-node/start.sh` 应保持仅 root 可读。
- 怀疑泄露时，在 **设备分组** 中重新生成 token，并重新执行各节点的对接命令。

UOT 使用面板派生的独立 HMAC 密钥做相邻节点认证，静态 token 不直接在链路上传输；但 UOT **不加密业务 payload**。敏感业务仍应使用 TLS、WireGuard、QUIC、Shadowsocks 等端到端加密。

## 备份

升级和重大配置变更前备份：

- `/opt/relay-panel/.env`
- SQLite 数据库文件，或 PostgreSQL 的一致性备份
- 当前使用的 Compose 和反代配置

备份应存放在不同磁盘或不同机器，并定期做一次恢复演练。只有“能恢复”的备份才有意义。
