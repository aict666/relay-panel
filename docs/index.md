---
layout: home

hero:
  name: RelayPanel
  text: 自托管端口转发，从这里开始
  tagline: 一套面向实际运维的中文指南，覆盖面板部署、节点接入、TCP/UDP 多跳、健康探测、UOT、TCP 0-RTT、安全升级与故障排查。
  actions:
    - theme: brand
      text: 5 分钟快速开始
      link: /guide/quick-start
    - theme: alt
      text: 查看 GitHub
      link: https://github.com/aict666/relay-panel

features:
  - icon: ⚡
    title: 快速部署
    details: Docker Compose 部署面板，Linux 一行命令接入 amd64 或 arm64 转发节点。
    link: /guide/quick-start
    linkText: 开始安装
  - icon: 🔀
    title: TCP / UDP 多跳
    details: 支持直连与多跳链、六种目标选择策略、主动健康探测和自动熔断。
    link: /guide/rules
    linkText: 创建规则
  - icon: 🚀
    title: UOT 与 0-RTT
    details: TCP/UDP 混合链可启用认证 UOT；节点间 TCP 使用 best-effort TCP Fast Open。
    link: /ADVANCED-ROUTING-UOT
    linkText: 了解边界
  - icon: 🛡️
    title: 安全升级
    details: 协议版本检查、节点滚动升级、低风险规则验证和快速回滚步骤一应俱全。
    link: /guide/upgrade
    linkText: 升级前必读
  - icon: 🩺
    title: 故障排查
    details: 从节点离线、端口不通、WebSocket 到 UOT/TFO，按症状快速定位问题。
    link: /guide/troubleshooting
    linkText: 开始排查
  - icon: 🔎
    title: 全站搜索
    details: 搜索命令、环境变量或错误关键词，直接跳到最相关的操作步骤。
---

## 推荐阅读顺序

第一次使用时，依次完成[快速开始](/guide/quick-start)、[核心概念](/guide/concepts)和[创建转发规则](/guide/rules)。准备升级已有环境时，直接从[安全升级与回滚](/guide/upgrade)开始。
