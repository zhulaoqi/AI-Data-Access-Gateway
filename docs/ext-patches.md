# SQL Gateway 扩展补丁（`adg_ext`）说明

本 fork 在上游 ADG 之上叠加 SQL Gateway 所需的能力（行级过滤、方言感知校验、准入控制、
ClickHouse/StarRocks 连接器、先审计后执行、同步 API、委托查询、审计查询）。所有新增逻辑都在
`src/adg_ext/` 内，对上游源码只有最小的“钩子”修改。总开关：`ADG_EXT_ENABLED`（默认 `false`；
关闭时行为与上游一致，上游测试套件全量通过）。环境变量前缀 `ADG_EXT_`。

## 1. 对上游的改动点（冲突面）

| 文件 | 改动 | 作用 |
|---|---|---|
| `src/adg/gateway_runtime/tools.py` | `execute_query` 在 `ext_enabled()` 时委托给 `adg_ext.pipeline.run` | 全部执行链路（行过滤/准入/审计/超时/KILL） |
| `src/adg/masking/service.py` | `strategy == "null"` 返回 None | 脱敏策略 `null` |
| `src/adg/policy/runtime.py` | `ext_hooks.field_denied`（2 处） | 封闭列范围 |
| `src/adg/app/main.py` | `ext_install(app, factory)` | 挂载 `/admin/ext/*`、`/ext/delegated/*` |
| `src/adg/app/dependencies.py` | 吊销名单检查 | 凭据吊销立即生效 |
| `src/adg/admin_api/console.py` | 新增 `entry` scope、`key_hash` | 入口服务凭据、外部哈希 Key |
| `src/adg/control_plane/services/api_key_service.py` | 支持外部提供 `key_hash` | 明文不落地 |
| `src/adg/control_plane/models/__init__.py` | 导入 `adg_ext.models` | `ext_*` 表共用元数据 |
| `src/adg/control_plane/migrations/versions/202610140001_ext_tables.py` | 新增迁移 | `ext_*` 表（关闭补丁时也无害） |
| `src/adg/sql_guard/guard.py` | `SqlGuard(dialect=…)` | 按方言解析/生成 SQL |
| `tests/integration/test_migrations.py` | 迁移链期望值 | 新增一条迁移 |

新增的审计查询（PA-7）没有改动任何上游文件：`src/adg_ext/audit_query.py` 与 `router.py` 里的
`audit_router`（`/ext/audit/*`），由 `adg_ext.app.install` 挂载，因此扩展关闭时不暴露。

## 2. 同步上游的步骤

1. `git fetch upstream && git checkout sqlgw/main && git merge upstream/main`（或 rebase）。
2. 冲突只可能出现在上表文件中，逐个核对钩子是否仍在原位置。
3. 运行：`.venv/bin/pytest -q -p no:cacheprovider`（含 `tests/ext`、`tests/regression`；
   `tests/ext_integration` 需要 `docker compose -f docker-compose.ext.yml up -d`）。
4. `.venv/bin/ruff check|format` 与 `.venv/bin/mypy` 只作用于 `src/adg_ext`、`tests/ext*`，
   不要格式化上游目录。
5. 升级 `sqlglot`/`mcp` 时必须重新跑 B 系列回归（`tests/regression/test_ext_bypass_regression.py`）。

## 2.1 审计查询接口（PA-7）

`GET /ext/audit/events`、`GET /ext/audit/events/{id}`、`GET /ext/audit/stats`，`admin` 作用域（复用
`require_ext_admin`：`runtime`/`entry` 密钥 403，并受 `ADG_EXT_ADMIN_ALLOWED_CIDRS` 约束）。契约、字段与错误码见
`sql-gateway/api/executor-admin.md` §9。实现要点：

- 全部过滤在 SQL 层完成；`table`、`reason`、`status` 的 `LIKE` 只用转义后的输入（转义符 `!`，`%`、`_` 与转义符本身都被转义）。
- `grantIds` 以授权 ID 传入，经 `User.external_ref = gw:user:<id>` 映射到审计的 `user_id`；响应 `grantId` 反向映射。
- 时间窗口默认最近 24 小时、最长 93 天；`limit` 默认 50、上限 200；`offset` 上限 10000；越界返回 422。
- 列表永不含 SQL；详情含 `sqlText`/`rewrittenSql`/`accessedFields`，每次成功读取经 `AuditService.record_sql_view` 写 `audit_sql_view`。
- **`requestId`、`channel`**：每条查询类审计行（放行的 `started`/`completed`，以及 Guard、权限、准入拒绝）的元数据都带
  `channel` 与（有则）`request_id`。委托查询由 `delegated.py` 校验后传入（`channel` 缺省 `jdbc`，须匹配
  `[a-z][a-z0-9_.-]{0,31}`；`requestId` 最长 200），MCP/HTTP 运行时路径没有传入，`pipeline._audit_meta` 补
  `channel=mcp`。被拒绝的事件改走 `pipeline._record_rejection`（与上游 `_record_rejection` 等价，只是多写元数据），
  **没有修改上游 `tools.py`**。列表项与详情输出 `requestId`、`channel`，列表支持 `?requestId=`、`?channel=`：
  对元数据 JSON 做 `LIKE`，模式是带引号的 `"request_id":"<值>"`（`json.dumps` 转义，通配符转义），所以是精确匹配、
  不会被 SQL 文本里的相似片段伪造；MySQL 默认排序规则下不区分大小写。
- 测试：`tests/ext/test_ext_audit_query.py`（SQLite）；`tests/ext_integration/test_extint_audit.py`
  （真实 MySQL 8.4 查询产生的审计行，并把同一套单测在 MySQL 控制面库上重跑，使用库 `adg_audit_cp`）。

## 2.1.1 封闭列范围对「目录里没有的列」同样生效（`analyze.rewrite`）

之前只有目录（`ResourceField`）里**已知**的列才会与授权列比对，目录里没有的列放行到库端。ClickHouse 的
`system.columns` 只列出账号有列级授权的列，于是未授权列（目录里没有）被放行，库端报权限错误，客户端只见
`connector_operation_error`（MySQL 因账号是库级授权、列都在目录里，所以由 Guard 直接拒绝）。现在
`rewrite` 对 `accessed_fields` 中每个名字：没有任何受限表**允许**它、不是语句自己定义的别名（`expr AS name`）、
也不是某个无限制表的列时，一律 `column_not_allowed:<col>`。三个引擎行为一致；同时堵住「目录之后新增的列」被
读出的缺口。没有改任何上游文件，122 个绕过回归样本不变。测试：`tests/ext/test_ext_analyze.py`
（目录缺列、别名不误伤、无限制表的列）与 `tests/ext_integration/test_extint_clickhouse.py`
（真实 ClickHouse，列级授权账号；该用例在改动前稳定复现 `status=error`）。

## 2.1.2 依赖：`clickhouse-connect`

`pyproject.toml` 早已声明 `clickhouse = ["clickhouse-connect>=0.8.0"]`（上游约定的可选依赖组），`all` 也包含它，
但 `uv.lock` 没随之更新，所以 `Dockerfile` 的 `uv sync --frozen --extra all` 装不上它。用 `uv lock` 补锁：只
**新增**了 `clickhouse-connect 1.10.0` 及其依赖 `lz4`、`urllib3`、`backports-zstd`，其余版本未变；镜像源保持锁文件原有
的清华镜像；顺带补上 `mcp` 约束 `<2`（pyproject 已有，锁里漏了）。锁文件头的 `revision` 因 uv 版本由 3 变为 5。
验证：`uv sync --frozen --no-dev --extra all` 到独立环境后 `import clickhouse_connect` 与
`adg_ext.clickhouse` 可用。未改 `pyproject.toml`，没有新增 `ext` 组（沿用既有的 `clickhouse`/`all`）。

## 2.1.3 行过滤派生表只列允许列（联调缺陷 N-2，`rowfilter.inject` / `analyze._predicate`）

**现象**：MySQL 数据源上，授权只要带行过滤，任何查询都失败（`connector_operation_error`）。**根因**：行过滤把受限表
改写为 `(SELECT * FROM t WHERE <filter>) AS t`，而管理服务给库账号的是**列级** `SELECT`（最小权限）；MySQL 对
`SELECT *` 要求全部列权限，库端报 1142/1143。ClickHouse 恰好会把 `*` 收窄为账号可访问的列，所以不受影响。

**修复**：派生表改为显式列出该授权的**允许列**（`allow` 去掉 `deny`，按名字排序，标识符一律加引号）：
`(SELECT `a`, `b` FROM t WHERE <filter>) AS t`。细节：

- 目录（`ResourceField`）已知且非空时，只列目录里存在的允许列（库里已删除的列不会拖垮整张表）；目录未知则列出全部允许列。
- **行过滤读取的列必须是允许列**（`allow` 且不在 `deny`）。账号只对允许列有 `SELECT`，过滤表达式读取其他列在库端必然
  失败；现在在改写阶段直接拒绝：`row_filter_column_not_permitted:<col>`（`permission_rejected`）。**不会**放开列权限，
  **不会**丢掉或忽略过滤。允许列为空时拒绝 `row_filter_no_permitted_columns`。多个角色（过滤以 OR 合并）逐个检查。
  列名比较不区分大小写。
- `verify` 的二次校验同步收紧：包装 SELECT 的投影必须**恰好**等于该授权的允许列（不是 `*`、不多列、不少列、不带表前缀、
  不是表达式），否则 `row_filter_verification_failed`。`Binding.columns=None` 仍表示旧的 `*` 投影，仅供不建模列范围的单测。
- 派生表本身不暴露任何允许列之外的物理列，因此「别名遮蔽」（`id AS ssn`）与「子查询绕过」都碰不到未授权列。
- **用户语句里的 `SELECT *` / `t.*` 仍然被拒绝**（`wildcard_projection_not_allowed`，带 `allowed_columns` 提示）：
  这是既有的、回归样本（`SELECT * FROM shop.orders` 等）强制要求的行为，脱敏也依赖投影位置，所以没有改为「展开为允许列」。
  即使将来放开，派生表也只会返回允许列。
- 没有修改任何上游文件；只改 `adg_ext/rowfilter.py`、`adg_ext/analyze.py`。

测试：`tests/ext_integration/test_extint_rowfilter_columns.py`（真实 MySQL 8.4 / ClickHouse，**列级授权账号 + 行过滤**；
MySQL 用例在改动前稳定复现 `status=error`，并含「库端确实拒绝 `SELECT *`」的前提断言；覆盖别名、JOIN、子查询、CTE、
脱敏、未授权列、过滤读取未授权列）、`tests/ext/test_ext_analyze.py`、`tests/ext/test_ext_rowfilter.py`、回归样本
`tests/regression/test_ext_bypass_regression.py`（新增 `ROWFILTER_DENY` 17 条 × 两个方言与 `ROWFILTER_ALLOW` 11 条 × 两个方言；
原 122 个样本不变，仅把「包装层必须是 `select * from`」的断言改为「包装层是不含 `*` 的列清单」）。

## 2.2 Prometheus 指标（`/admin/ext/metrics/prometheus`）

`GET /admin/ext/metrics/prometheus`，文本格式 0.0.4（`text/plain; version=0.0.4; charset=utf-8`）。复用
`require_ext_admin`：只允许 `admin` 作用域密钥（`runtime`/`entry` 403，无密钥 401），并受
`ADG_EXT_ADMIN_ALLOWED_CIDRS` 约束；`ADG_EXT_ENABLED=false` 时不挂载（404）。原 JSON 端点
`GET /admin/ext/metrics` 保持不变（键与含义都不变）。纯标准库实现（`src/adg_ext/metrics.py`，环境里没有
`prometheus_client`，未新增依赖）。

| 指标 | 类型 | 标签 | 说明 |
|---|---|---|---|
| `adg_ext_query_total` | counter | `outcome` = `completed`/`failed`/`timeout`/`cancelled`/`rejected` | 受管查询按结果计数；五个取值启动即为 0。`rejected` 含 Guard、权限、准入、`audit_unavailable` 拒绝；`failed` 是放行后执行失败（数据源不可用、连接器错误等） |
| `adg_ext_query_rejected_total` | counter | `reason` | 拒绝原因码取**第一个冒号之前**的部分（`column_not_allowed:ssn` → `column_not_allowed`）；一次拒绝含多个原因码时每个各计一次；原因须匹配 `[a-z][a-z0-9_]{0,63}`，否则记为 `other`；至多 64 个不同取值，溢出并入 `other` |
| `adg_ext_admission_wait_seconds` | histogram | `le` | 排队等待分布，桶 5ms…60s；放行的请求与等待后被拒（`queue_timeout`/`datasource_busy`/`revoked`）的请求都计入，`queue_full`/`circuit_open` 瞬时拒绝不计 |
| `adg_ext_admission_datasource_limit` | gauge | `datasource` | 数据源并发上限（`ADG_EXT_DATASOURCE_MAX_CONCURRENCY`，全局同一值），覆盖所有出现过运行或熔断状态的数据源 |
| `adg_ext_audit_unavailable_total` | counter | — | 因审计写入失败而拒绝的请求数（同时计入 `rejected`） |
| `adg_ext_revocation_poll_age_seconds` | gauge | — | 距上次**成功**拉取吊销名单的秒数（从未成功则为进程内缓存创建后的秒数）；未配置 `ADG_EXT_REVOCATION_URL` 时不输出 |

另输出与 exporter 同名的准入指标，exporter 可整体下线：`adg_ext_admission_queued`、
`adg_ext_admission_running`、`adg_ext_admission_datasource_running{datasource}`、
`adg_ext_admission_breaker_state{datasource}`、`adg_ext_admission_admitted_total`、
`adg_ext_admission_rejected_total{reason}`、`adg_ext_admission_wait_seconds_avg`。**没有** `adg_ext_up`、
`adg_ext_scrape_*`（抓取是否成功由 Prometheus 自带的 `up` 表示）。

标签只来自封闭或有界集合：不含用户、SQL、密钥、错误信息；`datasource` 是执行器数据源 ID。计数器是进程内的，
重启归零（Prometheus 的 `increase`/`rate` 会处理）。测试：`tests/ext/test_ext_metrics.py`（格式、标签、
基数、直方图、吊销名单新鲜度、端点权限与 CIDR）、`tests/ext_integration/test_extint_metrics.py`
（真实 MySQL：成功/拒绝/超时/取消/失败/审计不可用/排队拒绝后计数增加）。

## 2.3 吊销「墓碑」与重放（K-3）

同步 API 把已吊销的对象当作墓碑，**不靠新表**，直接用吊销后仍保留的原生行：

- 凭证：被删除（`DELETE`）、随用户删除或在执行器侧吊销的 `ApiKey` 行保留（`status=revoked`）。对同一 `keyHash`
  重放 `PUT credential`、或对一个已吊销凭证的同步对象改内容再 `PUT`，一律返回 **409**，响应体
  `{"detail":"credential_revoked"}`，不恢复授权（原先是唯一约束冲突导致的 HTTP 500）。`keyHash` 被另一个仍有效的
  凭证占用时返回 409 `key_hash_conflict`。
- 用户：`DELETE user` 把用户置为 `disabled`（并清掉角色与授权参数）。对其重放 `PUT user` 返回 409
  `user_revoked`；因此「删除后重放 user + credential」不再恢复授权（此前 `PUT user` 会把用户重新置为 `active`）。
- 显式解除：`POST /admin/ext/sync/{user|credential}/{name}/reinstate`（admin 范围）→ `{"reinstated": true|false}`，
  幂等。用户：恢复为 `active` 但**不带角色**（什么都不授予，之后需正常 `PUT user`）；凭证：把已吊销行的 `key_hash`
  改成不可匹配的 `retired:<id>`，释放唯一键，之后才能用同一摘要创建**新**凭证（管理服务吊销名单里的该摘要仍会让
  认证失败）。
- 哈希未变的 `PUT` 仍沿用幂等短路（返回 200、不执行任何处理），因此不会恢复授权，但也不会报 409。

管理服务一侧的影响：对这些 409 按 `executor-admin.md` §5「其他 4xx → 该对象失败，指数退避重试」处理，会持续重试直到对象被
管理服务自己删除；如需要「重新启用同一授权」，必须先调用 `reinstate`。测试：
`tests/ext/test_ext_sync_tombstone.py`、`tests/ext_integration/test_extint_runtime.py`
（`test_k3_*`、`test_replaying_user_and_credential_after_a_delete_*`）。

## 3. 安全不变量

- 行过滤基于解析后的 AST 注入，参数为带类型的字面量；注入后会二次 `verify`，任何不确定均拒绝（fail-closed）。
- 行过滤派生表只投影允许列，过滤表达式只能读允许列（2.1.3）；库账号的列级授权必须覆盖 `allow` 去掉 `deny` 的全部列。
- 无法重新解析的改写结果、`LIMIT … BY`、`WITH ROLLUP/TOTALS`、`INTO OUTFILE`、表函数、系统库等均被拒绝。
- 审计在执行前提交；写入失败则拒绝执行（`audit_unavailable`）。
- 日志与响应不包含管理 Key、明文凭据、数据库密码；Prometheus 标签不含用户、SQL、密钥（见 2.2）。
- 已吊销的凭证与已删除的用户不会被同步重放恢复，须显式 `reinstate`（见 2.3）。

## 4. 已知限制

- StarRocks 通过 doris 方言适配，**尚未在真实 StarRocks 上验证**。
- MySQL 没有服务端按用户的查询超时，只有看门狗 + `KILL QUERY`。
- 未实现 StarRocks resource group classifier。
- 字符串字面量中的 `:name` 会被 `text()` 当作绑定参数，结果是失败关闭。
- 有效行数上限受 `runtime_query_max_limit`（默认 1000）约束。
- 行过滤派生表假定库账号对**全部**允许列有 `SELECT`（管理服务按 `allow` 授权）。若库里实际授权比 `allow` 窄且目录又不反映
  （MySQL 的目录来自管理账号之外的扫描，可能列出账号读不了的列），该表上带行过滤的查询会在库端失败；需要管理服务保持授权与 `allow` 一致。
- 行过滤读取的列必须在 `allow` 里（且不在 `deny`）；把过滤列设为「只用于过滤、不对外开放」目前不支持，会被明确拒绝。
- 审计查询的 `table`、`status` 过滤使用 `LIKE`，不走索引，依赖时间窗口先行（≤93 天）与 `offset` 上限控制成本。
