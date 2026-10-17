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
| `src/adg/app/dependencies.py` | 吊销名单检查；PA-8：`authenticate_api_key_value` 开头 `enforce.check_source`、鉴权失败计数、通过后 `enforce.check_grant`（均为 `ext_enabled()` 下才生效） | 凭据吊销立即生效；来源黑名单与冻结授权（2.8） |
| `src/adg/app/main.py` | `FastAPI(..., **ext_app_kwargs())` | `/docs`、`/redoc`、`/openapi.json` 默认关闭（2.6） |
| `src/adg/shared/crypto.py` | `_decrypt_v2_envelope` 经 `adg_ext.kdf_cache.derive_key` 取派生密钥 | PBKDF2 输出缓存（2.4）；扩展关闭时等同原调用 |
| `src/adg/control_plane/db.py` | `create_engine_from_url` 在扩展开启时带连接池参数 | 控制面连接池大小与等待超时（2.5） |
| `src/adg/admin_api/console.py` | 新增 `entry` scope、`key_hash` | 入口服务凭据、外部哈希 Key |
| `src/adg/control_plane/services/api_key_service.py` | 支持外部提供 `key_hash` | 明文不落地 |
| `src/adg/control_plane/models/__init__.py` | 导入 `adg_ext.models` | `ext_*` 表共用元数据 |
| `src/adg/control_plane/migrations/versions/202610140001_ext_tables.py` | 新增迁移 | `ext_*` 表（关闭补丁时也无害） |
| `src/adg/sql_guard/guard.py` | `SqlGuard(dialect=…)` | 按方言解析/生成 SQL |
| `src/adg/control_plane/migrations/versions/202610150001_widen_audit_query_id_and_ext_columns.py` | 新增迁移 | `audit_events.query_id` 36→64 等（2.7） |
| `src/adg/audit/models.py` | `query_id` 改为 `String(64)`；`sql_text`/`metadata_json`/`resource_ids_json` 在 MySQL 上用 MEDIUMTEXT（`LargeText`） | 与迁移一致，`create_all` 路径同样生效（2.7） |
| `tests/integration/test_migrations.py` | 迁移链期望值 | 新增两条迁移 |

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
- `datasourceId` 可传逗号分隔的多个执行器数据源 ID（≤ 200，超出返回 422 `too_many_datasource_ids`），管理服务据此把开发者限定在自己维护的数据源上。
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

## 2.4 PBKDF2 派生缓存（PER-1）

**证据**：压测报告里默认配置下额外延迟 P95 约 160–670 ms，把 `ADG_SECRET_KDF_ITERATIONS` 降到 1200 后降到 31–55 ms。
剖析（给 `derive_pbkdf2_fernet_key` 打计时与调用栈）结果：**每个查询恰好一次 PBKDF2**，来自
`pipeline._run_connector → Datasource.config() → SecretConfigService.reveal_runtime_config → decrypt_fernet_envelope`
——即解密**数据源账号密码**的信封（迭代数取自信封本身，390 000 次约 45–130 ms CPU）。**API Key 与委托凭证的认证不涉及
PBKDF2**：API Key 是 `SHA-256(key)` 的索引查找，委托路径只做 `ext_sync_objects` 读取。所以「缓存已验证的凭证」没有收益，也
不做：不缓存任何授权结果，也就没有「吊销要主动清缓存」的问题。

**修复**：`adg_ext/kdf_cache.py` 缓存 **PBKDF2 的输出**（派生出的 Fernet 密钥），挂在 `crypto._decrypt_v2_envelope` 上：

- 派生是 `(主密钥, 盐, 迭代数)` 的纯函数，缓存不改变任何授权结果；Fernet 令牌（HMAC、时间戳）**每次仍完整校验**，迭代数范围
  检查在查缓存之前，**不降低迭代数、不放宽校验**。错误的主密钥、被篡改的信封、被改的盐或迭代数都得到各自的键，不会命中他人条目。
- 缓存键是 `HMAC-SHA256(进程内随机密钥, 主密钥‖盐‖迭代数)`，不是明文、也不是明文的哈希；值只在内存里，不落盘、不写日志、不经任何接口。
- 有上限（`ADG_EXT_KDF_CACHE_SIZE`，默认 64，LRU）和过期（`ADG_EXT_KDF_CACHE_TTL_SECONDS`，默认 300 秒）；任一为 0 即关闭。
  TTL 不涉及授权：吊销、删除用户、过期、墓碑都在认证与 `ext_sync_objects` 里先于、独立于该缓存判定，因此**不会让吊销生效时间超过原有
  5 秒目标**（测试在缓存已热的情况下逐项验证）。数据源账号换密码会产生新信封（新的随机盐），自然得到新键；主密钥轮换同理。
- 并发未命中合并为一次派生（single-flight）；派生失败不缓存、不会卡住等待者。
- **多进程**：每个 worker 进程各有一份缓存，互不共享，新进程每个数据源首次查询仍付一次派生（约 50–130 ms，一次性）。
- 默认值选择：64 条够覆盖数据源账号数（每个账号一个信封）；300 秒只是限制密钥材料在内存里的驻留时间（主密钥本来就常驻进程），
  不是正确性参数，缩短只会让每个 TTL 周期多付一次派生。

**前后对比**（同一台高负载开发机——负载 7–9，Docker 里 MySQL 8.4；执行器在本机 uvicorn，httpx 保活连接；做法同压测 S3：交替
「经网关一次查询」与「库上长连接直连同一语义语句」，300 对，逐次配对差值；每个设置各跑多次，波动来自机器负载）：

| 配置 | 额外延迟 P50 | 额外延迟 P95 | P99 | 运行次数 |
|---|---|---|---|---|
| 修复前（390 000 次，无缓存） | 61.6–63.6 ms | 77.0–116.2 ms | 108–164 ms | 3 |
| 缓存关闭（`ADG_EXT_KDF_CACHE_SIZE=0`，与修复前等价） | 61.3–65.7 ms | 91.5–113.8 ms | 116–149 ms | 3 |
| **修复后（390 000 次，缓存开启）** | **13.7–14.7 ms** | **23.3–33.8 ms** | 39–90 ms | 5 |
| 参照：迭代数 1200、缓存关闭 | 12.8–14.2 ms | 22.5–40.1 ms | 34–78 ms | 3 |

修复后与「把迭代数降到 1200」在波动范围内一致，而迭代数没有动。绝对值只代表这台机器这个时刻；压测报告里的 160–670 ms 来自另一种
并发形态（多线程、同机多容器），本表是单线程配对测量，不能直接对照。方法见 `tests/ext_integration/test_extint_bench.py`
（`ADG_EXT_BENCH=1`，默认跳过）。

测试：`tests/ext/test_ext_kdf_cache.py`（命中/键含全部输入/键不含明文/过期/LRU 上限/关闭/single-flight/失败不缓存/不写日志/
错误主密钥与篡改信封在缓存已热时仍失败/迭代数范围）、`tests/ext_integration/test_extint_kdf_cache.py`（真实 MySQL：多次查询只派生一次且
用信封自带的 390 000 次；委托路径同一份派生；缓存已热时删除凭证、删除用户、授权过期、凭证过期、吊销名单、墓碑重放都立即生效；
数据源账号轮换使用新信封）。

## 2.5 控制面连接池占满：不泄漏、不死锁，池满返回 503 `admission_pool_exhausted`

**现象**（压测报告）：多个授权同时排队时，所有请求停约 30 秒，之后部分 HTTP 500，日志
`QueuePool limit of size 5 overflow 10 reached, connection timed out, timeout 30.00`。复现：
`sql-gateway/scripts/loadtest/repro_inflight_stall.py`（5 授权 × 6 并发），或本仓库
`tests/ext_integration/test_extint_bench.py -k stall`。

**根因（线程转储为证）：不是连接泄漏，是「持有连接等待」造成的死锁**。请求的会话在认证时就借了一个控制面连接，
`pipeline._execute` 随后在**持有该连接**的情况下进入准入队列（最长 `queueTimeoutSeconds`，默认 30 s）。排队的请求越多，
池里被占住的连接越多；已经被放行、正在执行的请求在结束时需要一个连接写完成审计（`_persist`），却拿不到——而它们不结束，
排队的就永远等不到槽位。直到池超时（30 s）才解开。转储里 30 个请求中 15 个卡在 `_persist` 的 `pool._do_get`，其余在准入队列里
（各占一个连接）或在库上执行语句。取消、超时、异常路径都经 `finally: ticket.release()` 归还槽位与连接（压测后 `pool.checkedout() == 0`、
准入 `running/queued == 0` 由回归测试断言）。委托路径与运行时路径走同一个 `pipeline.run`，两者同样受影响，也同样被修复。

**修复**：

1. **排队前归还连接**（`pipeline.release_connection`）：等待准入前 `session.commit()`（此时没有待写内容；会话工厂是
   `expire_on_commit=False`，已加载对象继续可用），排队的请求不再占池。
2. **池等待有界**：扩展开启时控制面引擎使用 `ADG_EXT_CONTROL_PLANE_POOL_SIZE`（默认 10）、`..._POOL_MAX_OVERFLOW`（默认 30，
   合计 40 = 默认工作线程数）、`..._POOL_TIMEOUT_SECONDS`（默认 **5**，上游为 30）。
3. **池满返回明确的 503，不是 500**：任何路径（认证、读、审计写）拿不到连接时，`sqlalchemy.exc.TimeoutError` 由
   `adg_ext.app` 注册的处理器转成
   `HTTP 503`、头 `Retry-After: <ADG_EXT_POOL_EXHAUSTED_RETRY_AFTER_SECONDS，默认 1>`、响应体
   `{"status":"rejected","reason":"admission_pool_exhausted","detail":"admission_pool_exhausted","retry_after_seconds":1}`。
   与既有 `admission_*` 原因码同一词表（`reason` 同名字段，进 `adg_ext_query_rejected_total{reason="admission_pool_exhausted"}` 与
   `adg_ext_admission_rejected_total{reason="pool_exhausted"}`），但**用 HTTP 503 而不是 200**：此时没有控制面连接，无法写审计行，
   所以这类拒绝**没有审计行**（只有指标与日志）。放行后才拿不到连接（写开始审计行时）同样 503，槽位与熔断探针照常释放。
4. **数据源并发上限不超过运行时连接池**（`pipeline.effective_datasource_limit`）：`ADG_EXT_DATASOURCE_MAX_CONCURRENCY`（默认 20）
   与 `ADG_RUNTIME_DATASOURCE_POOL_SIZE + MAX_OVERFLOW`（默认 5 + 0）相互矛盾时，多放行的语句会停在连接器自己的池里（上游池等待 30 s），
   既不排队也不受排队超时约束；更糟的是等待连接超过了语句超时后，请求已返回 `query_timeout`，工作线程却仍在等池、之后照样执行
   （线程转储里有 4 个线程卡在 `relational.py` 的池取连接）。现在有效上限取两者较小值（gauge `adg_ext_admission_datasource_limit` 反映有效值）；
   要提高单数据源并发，同时调大 `ADG_RUNTIME_DATASOURCE_POOL_SIZE`。

**前后对比**（`test_extint_bench.py -k stall`，5 授权 × 每授权 6 并发，授权上限 3 / 队列 10 / 排队超时 30 s，语句超时 2 s，
真实 uvicorn，MySQL 慢查询）：

| | 最快请求 | 最慢请求 | 结果 |
|---|---|---|---|
| 修复前（3 轮） | 30.3–30.4 s | 37.8–38.3 s | 每一轮 30 个请求全部停约 30 s 才返回（含 4 个 `admission_queue_timeout`） |
| 修复后（4 轮，默认池 10+30/5 s） | 2.5–3.1 s | 13.8–14.9 s | 30 个全部按各自的语句超时返回 `query_timeout`，无 5xx/503 |
| 修复后（4 轮，仍用上游池 5+10/30 s） | 2.4–2.6 s | 14.0–14.6 s | 同上——死锁本身已消除，与池大小无关 |

修复后最慢约 14 s 只是 30 条各 2 s 的慢语句在 5 个连接上排队的串行时间（数据源有效上限 = 运行时池 5）。

测试（真实 MySQL 8.4，控制面为 file SQLite 加极小的 QueuePool）：`tests/ext_integration/test_extint_pool.py`——
8 个在途请求对 3 个连接的池，运行时与委托两条路径各一遍（修复前稳定出现 503，已用「去掉 `release_connection`」验证会失败），
断言全部 200、结束后 `pool.checkedout()==0`、准入无残留；连接被占满时两条路径都在约 1 s 内得到 503 + `Retry-After` 且不含 SQL/密钥，
释放后恢复，指标计数；放行后拿不到连接 → 503 且释放槽位；数据源有效上限等于运行时池容量。

## 2.6 关闭 `/docs`、`/redoc`、`/openapi.json`（N05）

`ADG_EXT_ENABLE_DOCS`（默认 `false`）。扩展开启（`ADG_EXT_ENABLED=true`）且该开关为假时，`create_app` 以
`docs_url=None, redoc_url=None, openapi_url=None` 构造应用，三个路径返回 404；`/mcp`、`/api/tools/*`、`/health` 与 `/admin`、`/ext`
不受影响。**默认值选择**：这三个页面无需认证，会暴露全部接口与模型，生产里没有理由开着；沿用本项目的正向命名风格
（`ADG_EXT_ENABLED`、`ADG_EXT_AUDIT_FAIL_CLOSED`），所以是「显式开启」而不是 `DISABLE_DOCS`，漏配时安全（关闭）。无效值（如
`maybe`）会让启动失败，而不是静默打开。开发环境需要时设为 `true`。`ADG_EXT_ENABLED=false` 时保持上游行为（页面可用）。
入口代理的路径白名单仍然是第二道防线（部署侧不应因此放松）。测试：`tests/ext/test_ext_docs.py`。

## 2.7 MySQL 控制库：列长度（`audit_events.query_id` 缺陷）与长度检查清单

**根因。** 审计表 `audit_events.query_id` 是 `String(36)`，而查询 ID 是 `qry_<uuid4>`（**40 字符**，`pipeline.py` 与上游
`tools.py` 都这样生成）。SQLite 不校验 `String(n)`，所有现有测试都跑在 SQLite 控制库上，所以没暴露；MySQL（严格模式，
Helm Chart 与生产的唯一模式）对 `INSERT` 返回 `Data too long for column 'query_id'`，放行后的「开始」审计行写不进去，
审计 fail-closed 把每条查询拒绝为 `audit_unavailable`（入口侧表现为 `audit_unavailable`）。

**修复（迁移 `202610150001`，接在 `202610140001` 之后）。** `batch_alter_table` 只放大，已有数据不动：

| 列 | 之前 | 之后 | 说明 |
|---|---|---|---|
| `audit_events.query_id` | `VARCHAR(36)` | `VARCHAR(64)` | 与 `decrypt_contexts.query_id` 同宽；索引 `ix_audit_events_query_id` 保留 |
| `ext_sync_objects.external_id` | `VARCHAR(64)` | `VARCHAR(256)` | row_filter 的外部 ID 就是对象名 |
| MySQL 专属：`audit_events.{resource_ids_json, sql_text, metadata_json}`、`ext_sync_objects.spec_json`、`ext_role_tables.{allow,deny,mask}_json`、`ext_row_filter_policies.{where_text, params_json}`、`ext_user_attributes.params_json` | `TEXT`（64 KB） | `MEDIUMTEXT`（16 MB） | 随语句/同步规格增长：审计行把 SQL 记两遍（原文 + 改写）；大角色规格（数百张表）轻易超过 64 KB |

- SQLite 没有 `ALTER COLUMN`，alembic 批处理模式重建表（索引与唯一约束随反射重建）；MySQL 直接 `MODIFY`。
  MEDIUMTEXT 只在 MySQL 上执行（其它方言 TEXT 无上限问题）。模型同步修改（`adg.audit.models.LargeText`），所以
  `Base.metadata.create_all`（上游测试/开发）与 `alembic upgrade head`（生产）得到同一份结构，有测试逐表逐列比对。
- 升级路径：空库 → head；旧版本（`202604260001`、`202610140001`）带数据 → head（行与索引保留）；`downgrade -1` 后再 `upgrade head`；
  重复 `upgrade head` 是空操作。`downgrade` 会把列收回去，MySQL 严格模式下若已有更长的值会报错拒绝（不静默截断）。
- **运维**：utf8mb4 下 `VARCHAR` 超过 255 字节（64×4=256）要改长度前缀，MySQL 对 `audit_events` 只能 `ALGORITHM=COPY`（建表拷贝，期间
  阻塞写入）。缺陷存在期间 MySQL 上不会有任何带 `query_id` 的行，表通常很小；Helm Chart 在 initContainer 里跑
  `alembic upgrade head`（滚动升级时旧 Pod 仍在服务），大表应先单独跑一次迁移。执行器镜像必须重建（迁移与模型都在镜像里）。
  kind 验证时手工执行过的 `ALTER TABLE audit_events MODIFY query_id VARCHAR(64) NULL` 与本迁移等价：之后再跑迁移是空操作（有测试）。
- **索引**：`query_id` 只做精确匹配（`=`，没有 `LIKE`），索引是整列索引：64×4=256 字节，远低于 InnoDB 的 3072 字节上限，
  不需要前缀索引；测试用 `EXPLAIN` 确认 `queryId` 过滤走 `ix_audit_events_query_id`。`requestId`/`channel` 仍是元数据 `LIKE`（见 2.1）。

**同类问题的全面检查（逐列对照实际生成值）。** 方法：遍历所有模型（上游 + `ext_*`）的字符串列，与代码实际能写入的最长值对照；
结论落在「入口校验」或「放大列」，测试里用代码自己的常量（`sync.MAX_NAME` 等）构造最长值，常量与列宽脱节会失败。

| 表.列（宽度） | 实际会写入的值 | 结论 |
|---|---|---|
| `audit_events.query_id`（36→64） | `qry_<uuid4>` = 40 | **修复（迁移）** |
| `audit_events.id/api_key_id/datasource_id`（36）、`user_id`（200） | uuidv7 = 36 | 足够 |
| `audit_events.event_type`（64）、`decision`（32） | `query_execution`、`permission_rejected` 等 ≤ 19；`allowed/denied/error/rejected` | 足够 |
| `audit_events.sql_text/metadata_json/resource_ids_json`（TEXT 64 KB） | 语句 + 改写语句 + 字段列表，随语句增长 | **MySQL 改 MEDIUMTEXT**（测试写入 >100 KB 的语句） |
| `decrypt_contexts.query_id`（64） | 40 | 足够（上游已是 64） |
| `users.external_ref`（200，唯一） | `gw:user:<grantId>` ≤ `MAX_NAME` | **入口校验**：`MAX_NAME` 由 256 改为 200，超出 400（见下） |
| `users.name`（200） | `principalName`（任意长） | **代码截断**到 200（仅展示） |
| `roles.name`（200，唯一）、`datasources.name`（200）、`api_keys.name`（200） | `gw:role:…`、`gw:ds:…`、`gw:cred:…` ≤ `MAX_NAME` | **入口校验**同上 |
| `api_keys.key_hash`（128） | SHA-256 = 64；墓碑 `retired:<id>` = 44 | 足够 |
| `roles.description`、`datasources.description`（TEXT） | `profileName`、`label`（任意长） | **代码截断**到 4000（`MAX_DESCRIPTION`） |
| `resources.name/display_name`（200）、`path`（512） | 扫描到的库/表名；`db.table` | **`fit_snapshot`**：放不下的条目不入目录（不可查询，日志告警）；MySQL/Doris ≤ 64，只会出现在 ClickHouse |
| `resource_fields.name`（200）、`data_type`（200） | 列名；ClickHouse `Enum8(…)`/`Tuple(…)` 可很长 | 列名过长的列不入目录；`data_type` 截断到 200（仅展示） |
| `resources.description`、`resource_fields.description`（TEXT） | 库内注释 | 截断到 4000 |
| `masking_policies.field_name`（200）、`subject_id`（200） | 必须是已扫描列名（≤200）；`role.id` = 36 | 足够 |
| `resource_policies.subject_id/subject_type/action`（200/32/64） | `role.id`、`role`、`read` | 足够 |
| `ext_sync_objects.name`（256）、`object_type`（32）、`hash`（64） | ≤ 200；`TYPES` 最长 18；校验为 64 | 足够 |
| `ext_sync_objects.external_id`（64→256） | row_filter：对象名（≤200）；其余 id = 36 | **修复（迁移）** |
| `ext_sync_objects.spec_json`、`ext_role_tables.*_json`、`ext_row_filter_policies.*`、`ext_user_attributes.params_json`（TEXT） | 整份规格、允许/禁止列表、模板 | **MySQL 改 MEDIUMTEXT** |
| `ext_*` 里的外键 id 列（36） | uuidv7 | 足够 |
| `request_id`（元数据 JSON，不是列；`delegated.MAX_REQUEST_ID` = 200） | ≤ 200 | 随 `metadata_json` 一起进 MEDIUMTEXT；测试用 200 字符的 `requestId` 走完整委托查询 |
| 上游其它表（`org_nodes`、`tags`、`*_tags`、`field_policies`） | 只由上游管理接口写入，扩展不写 | 未改动 |

- **不改的上游列**：为了不扩大冲突面，没有加宽 `users.external_ref` 等上游列，而是在入口把上限收到 200。这是对外契约的收紧
  （见 `sql-gateway/api/executor-admin.md` §4 的字段长度说明）：此前 201–256 字符的名字在这些类型上本来就会在库里失败。
- **仍可能超长、但不现实的值**：`datasources.config_json`（加密后的 host/账号/口令，TEXT）若总计 >64 KB；`audit_events.reason`（错误码，TEXT）。
- **测试**（`tests/ext_integration`，真实 MySQL 8.4）：
  `test_extint_mysql_controlplane.py`（运行时 + 委托查询 + 拒绝路径，控制库为 MySQL，结构由 `alembic upgrade head` 建；
  修复前稳定得到 `audit_unavailable`）、`test_extint_column_lengths.py`（最长值逐列写入、alembic/`create_all` 两种建表结构一致、
  >64 KB 语句的审计行、200 字符名字走完整同步与委托查询、索引与 `EXPLAIN`）、`test_extint_migrations.py`（SQLite 与 MySQL 上的升级路径；
  旧结构上 40 字符 `query_id` 确实被 MySQL 拒绝）；`tests/ext/test_ext_sync_limits.py`（名字上限、`fit_snapshot`）。

## 2.8 来源黑名单、授权冻结与风险聚合（PA-8，ADR-0027）

管理服务发布**只拉取、带版本**的黑名单（`blocklist:read` 令牌）；执行器每 5 秒拉一次，在本地回答两件事：
**这个来源 IP 是否被拦**、**这个授权是否被冻结**，热路径上不发任何网络请求。`ADG_EXT_BLOCKLIST_URL` 为空即整体关闭。

- 检查位置只有一个：`authenticate_api_key_value`。来源拦截在**检查凭据之前**，命中返回 403 `source_blocked`
  （对任何密钥、包括无效密钥与空密钥都一样，不泄漏密钥是否有效）；密钥通过后若其授权被冻结，返回 403 `grant_frozen`。
  入口（JDBC）走 `/ext/delegated/query`，来源地址取请求体 `clientIp`，授权取 `grantId`，在读取授权前先检查。
- `allow` 条目永远优先于 `deny`；条目自带 `expiresAt`，过期在本地即失效，无需回源。
- **取不到来源地址按放行处理**（MCP 在不透传来源的代理之后）；冻结授权仍然生效。
- 来源地址：`ADG_EXT_TRUSTED_PROXY_HOPS`（默认 0）为前置反向代理的层数。0 层时取 TCP 对端，忽略 `X-Forwarded-For`（任何调用方都能伪造）；
  N 层时取该头**从右数第 N 个**，更左的条目是客户端自填的，不采信。头缺失、非法或过短时回退到对端。
- 安全属性：拉取失败/返回异常不清空名单（保留最后一份好快照）；**全量快照**若会删掉超过
  `ADG_EXT_BLOCKLIST_SHRINK_GUARD_RATIO`（默认 0.5）的现有条目则拒绝（`adg_ext_blocklist_refused_total`），运维可用
  `POST /admin/ext/blocklist/refresh?force=true` 强制接受；增量不受影响。快照原子写入
  `ADG_EXT_BLOCKLIST_SNAPSHOT_PATH`（权限 0600），重启后即使管理服务不可达也能继续拦截；文件损坏则忽略。
- 被拦请求计数并**抽样**写一条审计行（每个来源、每个原因、每进程每分钟至多一条，`event_type=source_blocked`，不含 SQL、不含密钥），
  攻击流量不会变成数据库写入压力。
- 查询审计行新增：`client_ip`、`sql_fingerprint`（字面量替换为 `?`、`IN` 列表折叠后取 SHA-256 前 16 位，不含数据、不可逆）、`max_rows`。
  `GET /ext/audit/events` 的列表项与详情多出 `clientIp`、`sqlFingerprint`。
- `GET /ext/audit/aggregates?groupBy=…&from=&to=&nearPercent=`（`admin` 作用域，不含 SQL 文本、不含数据）：
  - `grant_source`：每个（授权，来源）的查询数、放行/拒绝、涉及表数、最大/累计行数、接近行数上限的次数。
  - `grant_reason`：每个（授权，拒绝原因码）的次数。
  - `fingerprint`：每个（授权，指纹）的次数、不同来源数、累计行数。
  - `auth`、`blocked`：鉴权失败（`invalid`/`revoked`/`expired`/`disabled`）与被拦次数，按来源与授权分组。
  前三种在窗口内最多扫描 `ADG_EXT_AGGREGATES_MAX_EVENTS`（默认 20 万）条，超过则 `truncated=true`，调用方不得当作完整结果。
- 指标：`adg_ext_blocklist_version`、`adg_ext_blocklist_entries`、`adg_ext_blocklist_poll_age_seconds`、
  `adg_ext_blocklist_refused_total`、`adg_ext_blocked_total{reason}`。
- 测试：`tests/ext/test_ext_risk.py`。

已知限制：`auth`、`blocked` 两类计数只存在于**进程内存**（按分钟分桶，保留 `ADG_EXT_RISK_COUNTER_RETENTION_SECONDS`，默认 26 小时）；
多副本部署时每个副本只看到自己的那一份，重启后清零。巡检把这两类当作「下限」使用。

## 3. 安全不变量

- 行过滤基于解析后的 AST 注入，参数为带类型的字面量；注入后会二次 `verify`，任何不确定均拒绝（fail-closed）。
- 行过滤派生表只投影允许列，过滤表达式只能读允许列（2.1.3）；库账号的列级授权必须覆盖 `allow` 去掉 `deny` 的全部列。
- 无法重新解析的改写结果、`LIMIT … BY`、`WITH ROLLUP/TOTALS`、`INTO OUTFILE`、表函数、系统库等均被拒绝。
- 审计在执行前提交；写入失败则拒绝执行（`audit_unavailable`）。
- 日志与响应不包含管理 Key、明文凭据、数据库密码；Prometheus 标签不含用户、SQL、密钥（见 2.2）。
- 已吊销的凭证与已删除的用户不会被同步重放恢复，须显式 `reinstate`（见 2.3）。
- 不缓存任何授权结果；PBKDF2 派生缓存只存派生密钥、键为 HMAC、有上限与过期、不写日志，吊销/删除/过期/墓碑不经过它（2.4）。
- 请求不在持有控制面连接时排队；拿不到连接是 503 `admission_pool_exhausted`，不是 500（2.5）。
- 生产配置下 `/docs`、`/redoc`、`/openapi.json` 默认不存在（2.6）。
- 来源黑名单只拒绝不放行：名单不可用时保留最后一份好快照，空/异常的快照不会清空名单；被拦请求不会泄漏密钥是否有效（2.8）。

## 4. 已知限制

- StarRocks 通过 doris 方言适配，**尚未在真实 StarRocks 上验证**。
- MySQL 没有服务端按用户的查询超时，只有看门狗 + `KILL QUERY`。
- 未实现 StarRocks resource group classifier。
- 字符串字面量中的 `:name` 会被 `text()` 当作绑定参数，结果是失败关闭。
- 有效行数上限受 `runtime_query_max_limit`（默认 1000）约束。
- 行过滤派生表假定库账号对**全部**允许列有 `SELECT`（管理服务按 `allow` 授权）。若库里实际授权比 `allow` 窄且目录又不反映
  （MySQL 的目录来自管理账号之外的扫描，可能列出账号读不了的列），该表上带行过滤的查询会在库端失败；需要管理服务保持授权与 `allow` 一致。
- 行过滤读取的列必须在 `allow` 里（且不在 `deny`）；把过滤列设为「只用于过滤、不对外开放」目前不支持，会被明确拒绝。
- 池耗尽的 503（`admission_pool_exhausted`）没有审计行（无连接可写）；`audit_fail_closed=false` 时放行后的语句在执行期间仍占用一个
  控制面连接（开始审计行与完成审计行在同一事务里），此时池容量应不小于同时执行数。
- 经 `/mcp`（流式 MCP 服务，挂载的子应用）进入的请求不经过上述 FastAPI 异常处理器；排队前归还连接的修复对它同样生效（同一个 `pipeline.run`），但池真的满了时它的表现由 MCP 框架决定（**未验证**，不保证是 503）。
- PBKDF2 缓存按进程；每个新进程每个数据源账号首次查询仍付一次派生。
- 同一数据库账号被多个数据源共用时，它们共享运行时连接池（缓存键是连接 URL），有效并发上限按单个数据源计算，不按池的使用者数。
- 审计查询的 `table`、`status` 过滤使用 `LIKE`，不走索引，依赖时间窗口先行（≤93 天）与 `offset` 上限控制成本。
- MySQL 控制库的 `audit_events.created_at` 是秒精度（`DATETIME`）：MySQL 对小数秒**四舍五入**，后半秒写入的行会存成「下一秒」，
  即晚于默认窗口终点（`now`）。因此紧接着查询之后、不带 `to` 的审计列表可能暂时看不到它（下一秒起可见）。`to` 取稍晚的时间即可，
  对账按 `requestId` 重试一次也行；集成测试里显式传了 `to`。
- 迁移里对 `audit_events` 的改列在 MySQL 上是整表拷贝（2.7），大表应在低峰、放流量前执行。
- 控制库为 PostgreSQL 的路径使用同一迁移（`batch_alter_table`），**未在真实 PostgreSQL 上验证**。
- 基线迁移给 `datasource_tags`/`resource_tags` 多建了一个 UNIQUE 索引而模型没有（上游既有差异，与扩展无关），结构一致性测试对这两张表只要求「迁移 ⊇ 模型」。
