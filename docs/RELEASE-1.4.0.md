# Panel 1.4.0 / Node 1.3.12 发布运行手册

## 交付边界

本版面向现有的 **兑换码充值 → 账户余额 → 套餐购买/续费** 模式，不是第三方在线支付平台。没有支付宝/微信支付网关、支付回调、自动退款或财务总账对账；不要在运营文案中宣称已支持这些能力。

- 月付提前付款预购未来 30 天周期，当前用量不重置。预付周期按保存的权益快照生效，不再次扣款，也不受后来商品改价、隐藏影响。
- 存在未使用的预付周期时，禁止直接切换、清除或改期，避免覆盖已付款权益。退款/转移须另行设计，不能绕过校验直接改库。
- 购买、自动续费、兑换、余额调整与流水同事务；订单保留交易号、操作者、权益及周期。历史只创建期初余额，不伪造历史收支。
- 免费注册套餐开通试用及线路；收费注册套餐只记录意向，首次付款才开通。存量账户仅在无订单、无用量、无规则且无任何线路授权时转待开通；其余历史授权保留供人工核对。
- 流量是最终一致计量，不是逐字节实时硬额度：按面板接收批次时的当前周期入账，有上报、60 秒周期调度和配置传播延迟。跨边界迟到流量不按传输时间拆分。
- 节点 outbox 保证已封装待确认批次重启重放。尚未封装的内存增量在硬退出时仍可能丢失；需要逐字节耐久结算的产品不能直接使用这套保证。

## 版本与升级顺序

| 项目 | 候选版本 |
|---|---|
| Panel / 配套前端 | 1.4.0 |
| Node / 安装脚本 | 1.3.12 |
| SQLite 追加迁移 | 60–63 |
| PostgreSQL 追加修订 | 45–48 |
| 节点配置协议 | v11，不变 |

先更新 **Panel + 同版前端**，再灰度 Node。旧节点可以上报，但不具备新批次去重保证；新节点不能先连旧 Panel 来获取可靠记账保证。

Panel 发行镜像及 Node 静态二进制覆盖 AMD64/ARM64；Node 发行 Docker 工作流仍仅发布 AMD64 镜像，ARM64 节点使用静态安装包或自行原生构建，不要在 ARM64 上直接选用该发行节点镜像。

旧 API 客户端需要同步修改：购买提交 `request_id`、确认价格/商品版本/当前套餐；编辑余额提交 `expected_balance`；开启自动续费确认 `expected_plan_id`、价格和计费版本。缺字段安全拒绝。不同交易号是独立购买，不以时间窗口猜测重复操作。

## 上线前检查

1. 核对现有商品价格、月付类型、线路授权、不限额度（0）、规则上限（0 表示不限）。修复历史非法余额字符串后才能迁移；不要直接删除流水绕过错误。
2. `JWT_SECRET` 至少 32 字节，推荐 `openssl rand -hex 32`；更换密钥会使已有登录失效。强制使用 HTTPS，限制管理面板访问范围。
3. Panel 应用运行 uid 10001；默认 `/app/data` 旧 root 目录由入口脚本修正权限。自定义 SQLite 挂载应预先准备写权限。
4. 每个节点使用独立、可写、持久化的 `RELAY_NODE_DATA_DIR`；Compose 已添加 `node_data`。不要让多个节点共用目录，不要清除 outbox 来处理上报失败；更换凭据/面板 URL 后旧文件保留供核账。
5. 在业务数据库**副本**运行同版迁移和恢复演练；仓库自动测试只证明合成旧库可升级，不代替你的生产数据验收。
6. 确认以下自动门槛通过后才能发布；GitHub 双架构产物验收与生产灰度不属于本地测试结果。
7. 升级会规范化可解析的历史公告到期时间；无法解析的手工数据保留并输出带公告 ID 的告警，须在公告管理中核对并重新保存。

## 可复现验收

以下在隔离 Linux 环境执行，`TEST_PG_URL` 必须指向可创建临时数据库/模式的**测试实例**，不可指向生产。

```bash
export TEST_PG_URL='postgres://relaytest:测试密码@127.0.0.1:5432/relaytest'
export RELAY_REQUIRE_PG_TESTS=1
export RELAY_REQUIRE_LINUX_TFO_TEST=1
ulimit -n 65536
sudo sysctl -w net.ipv4.tcp_fastopen=3
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
bash scripts/check-repo-test-parity.sh
cargo build --workspace --locked
python3 tests/billing_upgrade_test.py
python3 -m unittest discover -s tests -p '*_unit_test.py'
python3 tests/billing_api_test.py
python3 tests/e2e_test.py
python3 tests/e2e_chain_test.py
CHAIN_MID=1 python3 tests/e2e_chain_test.py
bash scripts/deploy-web-mode-check.sh
bash scripts/relay-node-install-check.sh
```

前端在 `frontend/` 执行 `npm ci`、`npm run typecheck`、`npm run lint`、`npm test`、`npm run build`、`npm audit`。Rust 依赖使用 `cargo audit` 检查；不得通过忽略未知公告来“变绿”。

```bash
docker build --target panel -t relay-panel-candidate:local .
python3 tests/container_release_test.py relay-panel-candidate:local
bash scripts/release-check.sh panel 1.4.0
bash scripts/release-check.sh node 1.3.12
```

容器测试创建独立临时资源，验证 root 拥有的旧卷升级、非 root 应用、健康检查、字体 CSP、实际旧库备份与恢复。`panel-release` 同样在两种架构推送前执行；Node musl 产物在各自原生架构执行并确认静态链接。

HTTP 闭环测试覆盖收费注册待开通、充值、并发购买、流量去重、预购、余额冲突回滚、流水权限隔离/分页及商品隐藏后的原交易重放。双库契约另覆盖跨多期停机、暂停/封禁、已付线路保护、手动暂停保留与删号后财务记录保留。订单页面区分购买/预付，并展示成交权益周期，不用当前商品信息替代历史订单。

## 备份与回滚

- `deploy.sh` 先准备镜像、验证 Compose，再停止旧 Panel 并备份；源码构建在停机前完成。备份从旧容器实际 `DATABASE_URL` 取址，而不是新 `.env`。
- 默认备份在仓库 `backups/pre-upgrade-.../`，目录私有。可用 `RELAYPANEL_BACKUP_DIR` 指定私有外部目录；备份包含 `.env`、旧容器配置等密钥，必须离机加密保存，禁止入 Git。
- SQLite 复制停止后的完整 `/app/data`，验证 `integrity_check` 和用户表。自定义路径自动备份会拒绝，须自行协调备份；在线单库快照可用 `python3 scripts/backup-sqlite.py 源数据库 新备份文件`，它包含已提交 WAL 数据且不覆盖已有快照。
- PostgreSQL 使用 custom-format `pg_dump` 并解析归档目录。外部数据库默认用 `postgres:16-alpine` 工具；更高版本数据库应设置匹配的 `RELAYPANEL_PG_BACKUP_IMAGE`。全归档恢复演练仍须由发布前副本验收完成。
- 备份失败终止升级，并尝试启动原本运行的**原容器**；原本停止的服务不擅自启动。镜像启动/迁移失败后不自动回滚数据库，避免丢失升级后已经提交的资金交易。
- 真正回滚须先关闭购买、充值和节点写入，另存故障现场，再将**升级前数据库快照 + 原镜像 + 原配置**恢复到隔离位置验证。不要只退二进制、不退数据库；不要直接覆盖含有升级后订单的数据库。确认新增交易已人工对账后再切流。

## 发布操作

本轮只准备代码与本地候选产物，不自动提交、打标签、推送、发布镜像或操作生产。

授权发布后，用 `v1.4.0`、`node-v1.3.12` 两条独立标签触发流水线。流水线先执行完整 CI，再构建/验收产物；验证失败不移动 latest、不发布正式 Release。两架构都通过后，先对生产副本验收，再进行小流量灰度，核对余额、订单、流水、周期重置及入口单次计量。

Node 1.3.11 的首次远程发行在读取草稿资产时因任务权限不足被阻断，未正式发布；修正权限后使用新标签 1.3.12，不覆盖原标签。
