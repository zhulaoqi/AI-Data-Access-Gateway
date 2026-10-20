# AI Data Access Gateway

[English README](../../README.md)

AI Data Access Gateway 是一个面向 AI Agent 的开源安全数据访问网关，通过 MCP 协议为 AI Agent 提供数据库安全访问服务。它位于 AI Agent 与真实数据源之间，提供受管控的元数据发现与只读数据访问，并在 AI 发起的数据查询过程中执行鉴权、SQL 安全检查、字段级策略、脱敏、数据解密控制并记录审计日志。

## 架构概览

项目由数据安全访问层和管理控制台组成。

运行时数据访问层通过 SQL Guard、资源策略和字段策略限制查询，只允许受控的只读路径。资源策略可以作用于数据源、数据库、Schema、表或视图、标签或全局范围；字段策略与脱敏策略仍保持字段级控制。面向 AI Agent 的主入口是 FastMCP Streamable HTTP `/mcp` 端点；`POST /api/tools/{tool_name}` 是面向传统服务集成的补充普通 HTTP 工具接口，不是 MCP 传输入口。连接器依赖或执行失败会返回结构化的 `status: "error"` 响应，并包含稳定的 `error.type`、脱敏后的 `error.message` 与用于日志关联的 `query_id`；原始连接器、驱动、主机和 SQLAlchemy 异常文本不会进入运行时响应或审计 metadata。权限策略和 SQL Guard 拒绝仍返回 `status: "rejected"`。

管理控制台为单管理员信任模型服务，覆盖数据源维护、资源治理与审计查看等操作，负责数据源登记、目录身份映射、资源元数据、字段策略、脱敏配置与 API Key 管理、企业组织架构管理。

仓库还包含演示数据初始化、Docker Compose 启动方式，以及最小化的运行时 HTTP 调用示例。

![system architecture](./system-architecture.png)

## 管理界面示例

![mcp](./admin-pages-screenshot/mcp.png)

## 仓库布局

- `src/adg/`：后端应用、控制平面、运行时、连接器与安全能力
- `tests/`：后端单元与集成测试
- `web/`：React + Vite 管理控制台
- `examples/`：演示种子数据和示例客户端流程
- `docs/`：内部规划、设计、验收与仓库记忆文档

## 快速开始

推荐优先使用 Docker Compose 启动生产式运行栈；如果需要在宿主机上直接运行，也请使用非开发依赖、关闭 reload，并显式设置生产环境变量。

### 后端

```powershell
uv sync --frozen --no-dev --extra all
$env:ADG_ENV="production"
$env:ADG_CONTROL_PLANE_DATABASE_URL="sqlite:///./data/adg-control-plane.db"
$env:ADG_SECRET_KEY="<generate-a-long-random-secret>"
$env:ADG_CREDENTIAL_ENCRYPTION_KEY="<generate-a-second-long-random-secret>"
$env:ADG_MASKING_ENCRYPTION_KEY="<generate-a-third-long-random-secret>"
uv run --no-dev --extra all alembic upgrade head
uv run --no-dev --extra all init-admin --database-url sqlite:///./data/adg-control-plane.db
uv run --no-dev --extra all uvicorn adg.app.main:create_app --factory --host 0.0.0.0 --port 8000
```

`init-admin` 会输出一次性的管理员 API Key，用于控制台初始化和管理面配置。请立即保存，并在控制台中使用该值。运行时 HTTP 示例需要另一个绑定目录用户的 runtime 作用域 API Key，该 Key 需要在初始化完成后单独创建或重置。

### MCP 鉴权

对于 `/mcp`，可通过配置的 API Key 请求头或 Bearer 鉴权提供同一把 runtime 作用域 API Key：

- 默认或配置的 API Key 请求头（默认：`X-ADG-API-Key`）
- `Authorization: Bearer <runtime-api-key>`

Query 鉴权是默认关闭的兼容能力，仅用于无法设置请求头的平台。部署时显式设置 `ADG_MCP_QUERY_API_KEY_ENABLED=true` 后，才可使用 `/mcp?apikey=<runtime-api-key>`。系统特意不提供运行时或管理控制台开关，因为鉴权引导策略必须在请求进入应用前固定。

已启用来源同时提供不同的非空凭据时，`/mcp` 返回 HTTP 400。应优先使用请求头或 Bearer 方式。启用 query 鉴权后，代理、访问日志和监控系统不得保留完整查询串，因为其中可能暴露 API Key。

### 前端

```powershell
Set-Location web
npm ci
npm run build
```

生产构建产物会输出到 `web/dist`。Docker Compose 方案会使用 Nginx 托管该静态前端，并将 Web 控制台暴露在 `http://127.0.0.1:8080`。

### Docker Compose

```powershell
Copy-Item docker-compose.example.yml docker-compose.yml
$env:ADG_SECRET_KEY="<generate-a-long-random-secret>"
$env:ADG_CREDENTIAL_ENCRYPTION_KEY="<generate-a-second-long-random-secret>"
$env:ADG_MASKING_ENCRYPTION_KEY="<generate-a-third-long-random-secret>"
docker compose up --build
docker compose exec backend init-admin
```

`docker-compose.example.yml` 是纳入版本控制的模板文件。请先复制为 `docker-compose.yml`，再在复制出来的文件里调整端口、卷挂载或环境相关配置。如需使用包镜像源，请在 `.env` 中设置 `PYPI_INDEX_URL` 和/或 `NPM_REGISTRY_URL`；如果未设置，Docker 构建会使用 `https://pypi.org/simple` 和 `https://registry.npmjs.org/`。Compose 方案会启动生产环境的后端与静态前端容器，其中后端 API 与 MCP 接口默认暴露在 `http://127.0.0.1:8000`，AI Agent 需要使用不同宿主机端口时可在 `.env` 中设置 `ADG_BACKEND_HOST_PORT`。管理控制台展示 MCP 接入地址时会使用 `ADG_BACKEND_HOST_PORT`，并且只在端口为 `80` 或 `443` 时省略端口号。Web 控制台默认暴露在 `http://127.0.0.1:8080`；如果该宿主机端口已被占用，可设置 `ADG_WEB_PORT`。只有需要修改后端容器内部监听端口时，才需要设置 `ADG_BACKEND_PORT`。SQL Guard 分为执行模式和严格校验两层：`ADG_SQL_EXECUTION_MODE` 默认是 `read_only`，可设置为 `dml`、`schema` 或 `admin` 以放开更高风险的语句类别；`ADG_SQL_STRICT_VALIDATION` 默认是 `true`，用于控制函数与投影等严格限制。`ADG_SQL_REJECT_WILDCARD` 在代码里默认是 `true`（拒绝 `SELECT *`）；部署启动脚本目前设为 `false`，把 `*` 展开成该表已允许的列，改回 `true` 即重新拒绝。管理端资源、资源树和审计列表接口返回包含 `items`、`total`、`limit` 和 `offset` 的分页对象；可用 `ADG_ADMIN_PAGE_DEFAULT_LIMIT`（默认 `50`）和 `ADG_ADMIN_PAGE_MAX_LIMIT`（默认 `500`）调整默认分页。API Key 认证失败限流默认启用并使用进程内内存计数；可通过 `ADG_AUTH_RATE_LIMIT_ENABLED`、`ADG_AUTH_RATE_LIMIT_STORAGE`、`ADG_AUTH_RATE_LIMIT_WINDOW_SECONDS`、`ADG_AUTH_RATE_LIMIT_MAX_FAILURES` 和 `ADG_AUTH_RATE_LIMIT_BLOCK_SECONDS` 配置；`ADG_AUTH_RATE_LIMIT_MEMORY_MAX_BUCKETS`（默认 `10000`）用于限制进程内跟踪内存。多进程共享计数可设置 `ADG_AUTH_RATE_LIMIT_STORAGE=redis` 和 `ADG_AUTH_RATE_LIMIT_REDIS_URL`，并安装可选 `redis` extra。运行时数据源查询会通过进程内 LRU/空闲 TTL 缓存复用 SQLAlchemy Engine，可使用 `ADG_RUNTIME_DATASOURCE_POOL_CACHE_SIZE`（默认 `32`）、`ADG_RUNTIME_DATASOURCE_POOL_IDLE_TTL_SECONDS`（默认 `300`）、`ADG_RUNTIME_DATASOURCE_POOL_SIZE`（默认 `5`）和 `ADG_RUNTIME_DATASOURCE_POOL_MAX_OVERFLOW`（默认 `0`）调整。运行时查询、数据源连接测试和元数据扫描连接都会设置 DBAPI 超时：`ADG_RUNTIME_DATASOURCE_CONNECT_TIMEOUT_SECONDS`（默认 `10`）、`ADG_RUNTIME_DATASOURCE_READ_TIMEOUT_SECONDS`（默认 `120`，MySQL/Doris）和 `ADG_RUNTIME_DATASOURCE_WRITE_TIMEOUT_SECONDS`（默认 `120`，MySQL/Doris）。数据源凭据和 reversible 脱敏上下文使用版本化 Fernet envelope，并通过 PBKDF2-HMAC-SHA256 派生密钥；可用 `ADG_SECRET_KDF_ITERATIONS`（默认 `390000`）调整迭代次数。生产环境必须将 `ADG_SECRET_KEY`、`ADG_CREDENTIAL_ENCRYPTION_KEY` 和 `ADG_MASKING_ENCRYPTION_KEY` 设置为三个互不相同的长随机值。未显式指定 database 进行元数据扫描时，ADG 最多扫描 `ADG_METADATA_SCAN_MAX_DATABASES` 个数据库（默认 `25`）。连接器网络边界会在连接前拒绝 loopback、link-local metadata IP、multicast 和 unspecified 地址，同时允许常见 RFC1918 私有数据库地址；如需例外，可用 `ADG_DATASOURCE_NETWORK_ALLOWLIST` 配置逗号分隔的 host、IP 或 CIDR allowlist。

运行时查询支持非递归的只读 CTE：每个 CTE 及最终语句都必须是 `SELECT`；锁定读、`SELECT INTO`、通配符投影、动态 `LIMIT` 以及超过运行时最大值的 CTE `LIMIT` 都会被拒绝。若 CTE 查询引用的资源命中适用的脱敏策略，由于暂不支持跨 CTE 的脱敏血缘，会被安全拒绝。

完整资源树响应受 `ADG_ADMIN_RESOURCE_TREE_MAX_NODES`（默认 `10000`）限制，该预算合并计算资源、字段和标签关联；超出时接口返回 HTTP 413，不会返回容易被误认为完整结果的部分树。

运行时查询请求受 `ADG_RUNTIME_QUERY_MAX_LIMIT`（默认 `1000`）限制，`/runtime/decrypt` 批次受 `ADG_RUNTIME_DECRYPT_MAX_VALUES`（默认 `100`）限制；超过上限的请求会被明确拒绝，而不是静默截断。

## 贡献者验证命令

```powershell
uv sync --extra dev --extra all
uv run --extra dev pytest
uv run --extra dev ruff check .
uv run --extra dev mypy src tests
Set-Location web
npm test
npm run build
npm run audit:prod
Set-Location ..
uv export --frozen --extra dev --extra all --no-editable --no-hashes --no-emit-project --format requirements-txt --output-file .tmp-audit-requirements.txt
uv tool run --from pip-audit pip-audit -r .tmp-audit-requirements.txt --no-deps --vulnerability-service osv --progress-spinner off
Remove-Item .tmp-audit-requirements.txt
```

## 文档导航

- [安全策略镜像](security.md)
- [贡献指南镜像](contributing.md)
- [行为准则镜像](code-of-conduct.md)
- [English README](../../README.md)
- [English Security Policy](../../SECURITY.md)
- [English Contributing](../../CONTRIBUTING.md)
- [English Code Of Conduct](../../CODE_OF_CONDUCT.md)

## 许可证

项目采用 Apache 2.0 许可证。详情见 [LICENSE](../../LICENSE)。
