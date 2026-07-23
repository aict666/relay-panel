# 快速开始

本页带你完成一套最小可用部署：安装面板、登录、接入一个节点，再创建一条 TCP 转发规则。

## 部署前准备

- 一台可运行 Docker 和 Docker Compose 的 Linux 服务器，用于面板。
- 至少一台 amd64 或 arm64 Linux 服务器，用于 `relay-node`。
- 面板服务器可访问 GitHub Container Registry；节点可访问面板地址和 GitHub Releases。
- 防火墙放行面板 HTTP/HTTPS 端口，以及实际要使用的转发端口。

::: tip
面板和节点可以先装在同一台机器上验证，但正式使用时通常分开部署。节点仅支持 Linux。
:::

## 1. 安装面板

在面板服务器上以 `root` 身份执行：

```bash
curl -fsSL https://raw.githubusercontent.com/aict666/relay-panel/main/install.sh | bash
```

脚本会把项目安装到 `/opt/relay-panel` 并通过 Docker Compose 启动。安装完成后检查：

```bash
cd /opt/relay-panel
docker compose ps
docker compose logs --tail=100 panel
```

浏览器打开 `http://服务器IP:18888`。管理员用户名固定为 `admin`，初始密码由面板在首次建库时随机生成。执行下面的命令查看：

```bash
cd /opt/relay-panel
docker compose -f docker-compose.release.yaml logs panel
```

在日志中找到“RelayPanel 首次安装管理员凭据”，使用其中的密码登录。凭据只在初始化成功的那次启动中输出，不会在后续重启时重复生成；请妥善限制容器日志的读取权限。首次登录会强制修改密码。

从旧版本升级且管理员仍使用历史默认密码时，面板也会自动换成新的随机密码并在升级后的启动日志中输出。正式暴露到公网前，请完成[安全配置](/guide/security)中的 HTTPS 和防火墙设置。

## 2. 创建设备分组

管理员登录后进入 **设备分组**，创建一个入口分组：

- 分组名称：例如 `香港入口`。
- 端口范围：为该分组保留一段未被其他服务占用的端口。
- 线路倍率：个人使用可保持 `1.0`。
- 隐藏：只影响普通用户的节点状态页，不会停用线路或规则。

保存后点击 **复制对接命令**。命令已包含这个分组的节点 token 和面板地址，不要把它贴到公开 Issue、日志或聊天中。

## 3. 接入 relay-node

SSH 登录节点服务器，粘贴刚才复制的对接命令并以 `root` 执行。安装脚本会自动识别 amd64 / arm64、安装 systemd 服务并启动节点。

```bash
systemctl status relay-node
journalctl -u relay-node -n 100 --no-pager
```

回到面板的 **节点状态** 页面，通常 30 秒内会看到节点在线。若没有出现，转到[节点离线排查](/guide/troubleshooting#节点离线或反复上下线)。

## 4. 创建第一条规则

进入 **转发规则 → 新建规则**：

1. 选择刚创建的入口设备分组。
2. 协议选择 `TCP`。
3. 填写一个未占用的入口端口。
4. 目标填写 `目标域名或 IP:端口`。
5. 目标策略先选“固定首目标”。
6. 保存并启动规则。

从外部主机连接入口节点的公网 IP 和入口端口，确认业务能够访问。不要只在节点本机测试：云安全组、NAT 和运营商网络问题通常只有外部连接才能暴露。

## 5. 完成最小验收

部署完成至少应满足：

- `docker compose ps` 中面板服务正常。
- `systemctl is-active relay-node` 输出 `active`。
- 面板中节点显示在线，版本与当前 Release 一致。
- TCP 测试流量可通过规则抵达目标。
- 面板能看到连接数和流量增长。

下一步阅读[核心概念](/guide/concepts)和[创建转发规则](/guide/rules)，再配置 UDP、多目标或多跳链。
