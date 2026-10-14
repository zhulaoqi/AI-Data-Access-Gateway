# SQL Gateway 扩展补丁（`adg_ext`）说明

本 fork 在上游 ADG 之上叠加 SQL Gateway 所需的能力（行级过滤、方言感知校验、准入控制、
ClickHouse/StarRocks 连接器、先审计后执行、同步 API、委托查询）。所有新增逻辑都在
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

## 2. 同步上游的步骤

1. `git fetch upstream && git checkout sqlgw/main && git merge upstream/main`（或 rebase）。
2. 冲突只可能出现在上表文件中，逐个核对钩子是否仍在原位置。
3. 运行：`.venv/bin/pytest -q -p no:cacheprovider`（含 `tests/ext`、`tests/regression`；
   `tests/ext_integration` 需要 `docker compose -f docker-compose.ext.yml up -d`）。
4. `.venv/bin/ruff check|format` 与 `.venv/bin/mypy` 只作用于 `src/adg_ext`、`tests/ext*`，
   不要格式化上游目录。
5. 升级 `sqlglot`/`mcp` 时必须重新跑 B 系列回归（`tests/regression/test_ext_bypass_regression.py`）。

## 3. 安全不变量

- 行过滤基于解析后的 AST 注入，参数为带类型的字面量；注入后会二次 `verify`，任何不确定均拒绝（fail-closed）。
- 无法重新解析的改写结果、`LIMIT … BY`、`WITH ROLLUP/TOTALS`、`INTO OUTFILE`、表函数、系统库等均被拒绝。
- 审计在执行前提交；写入失败则拒绝执行（`audit_unavailable`）。
- 日志与响应不包含管理 Key、明文凭据、数据库密码。

## 4. 已知限制

- StarRocks 通过 doris 方言适配，**尚未在真实 StarRocks 上验证**。
- MySQL 没有服务端按用户的查询超时，只有看门狗 + `KILL QUERY`。
- 未实现 StarRocks resource group classifier。
- 字符串字面量中的 `:name` 会被 `text()` 当作绑定参数，结果是失败关闭。
- 有效行数上限受 `runtime_query_max_limit`（默认 1000）约束。
