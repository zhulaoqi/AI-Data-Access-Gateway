# Contributing

Chinese mirror: [简体中文](docs/zh-CN/contributing.md)

## Scope

AI Data Access Gateway is currently released as a V1 MVP. Contributions should prefer focused, reviewable changes over broad speculative refactors. Changes that materially affect release-facing behavior or documentation should stay explicit about current implementation boundaries.

## Prerequisites

- Python 3.12+
- Node.js 20+
- `uv`
- `npm`

## Local Setup

### Backend

```powershell
uv sync --extra dev --extra all
```

### Frontend

```powershell
Set-Location web
npm ci
Set-Location ..
```

## Verification

Run the relevant verification commands before opening a pull request.

### Backend

```powershell
uv run --extra dev pytest
uv run --extra dev ruff check .
uv run --extra dev mypy src tests
```

### Frontend

```powershell
Set-Location web
npm test
npm run build
npm run audit:prod
Set-Location ..
```

## Remotes

Push our branches to both remotes. A push that updates only one of them is incomplete. `main` and every feature branch follow this rule.

- GitLab: `git@gitlab.yeahmobi.com:gst/AI-Data-Access-Gateway.git`
- GitHub: `git@github.com:zhulaoqi/AI-Data-Access-Gateway.git`

`upstream` (`HanZephyr/AI-Data-Access-Gateway`) is the public upstream. Do not push our branches there unless someone explicitly asks.

`origin` points only at GitHub. A branch that tracks `origin` will skip GitLab on a plain `git push`. Track `gitlab` instead. That remote is configured with both push URLs, so one push updates both.

Configure it once. The first `--add --push` replaces the implicit push URL, so both URLs have to be added:

```bash
git remote add gitlab git@gitlab.yeahmobi.com:gst/AI-Data-Access-Gateway.git
git remote set-url --add --push gitlab git@gitlab.yeahmobi.com:gst/AI-Data-Access-Gateway.git
git remote set-url --add --push gitlab git@github.com:zhulaoqi/AI-Data-Access-Gateway.git
git push -u gitlab HEAD
```

Before the first push of a new branch, `git remote get-url --push --all gitlab` should list both URLs. After that, `git push` updates GitLab and GitHub together.

## Pull Request Expectations

- keep changes focused and reviewable
- update tests when behavior changes
- update English and Chinese docs together when release-facing docs change
- do not claim capabilities that the repository does not yet implement
- preserve unrelated user or teammate changes in the working tree
- explain any security, schema, or API-surface impact in the pull request description

## Development Notes

- Treat current code, tests, and runnable configuration as the source of truth.
- Historical design artifacts may provide context, but they should not override implemented behavior.
- If you need to make a larger change, split it into sequenced pull requests when practical so review and rollback remain straightforward.
