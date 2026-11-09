# AGENTS

## Repository Purpose

AI Data Access Gateway is a secure data access gateway MVP for AI agents. It exposes governed metadata discovery and read-only runtime data access with authorization, SQL safety checks, masking, runtime decrypt controls, and audit logging.

## Source Of Truth

- Current code, tests, and runnable configuration are the source of truth.
- Historical design docs under `docs/superpowers/specs/` are useful context but must not override the implemented repository state.
- If a historical design doc conflicts with current code, follow current code and update outward-facing docs accordingly.

## Important Directories

- `src/adg/`: backend application code
- `tests/`: backend unit and integration coverage
- `web/`: React + Vite admin console
- `examples/`: demo seed and example client flows
- `docs/en/`: English release-facing project docs
- `docs/zh-CN/`: Chinese mirror docs
- `docs/superpowers/`: internal planning, spec, acceptance, and repository memory artifacts

## Working Rules

- Keep release-facing English and Chinese docs in sync.
- Push our branches to both GitLab `gst/AI-Data-Access-Gateway` and GitHub `zhulaoqi/AI-Data-Access-Gateway`. Track `gitlab`, whose push URLs are both of those remotes. A branch tracking `origin` updates GitHub only and is not done. Do not push `upstream` (HanZephyr) unless explicitly asked. See CONTRIBUTING.md, section Remotes.
- Do not describe roadmap items as current features.
- Prefer minimal, bounded edits over broad unrelated cleanup.
- Do not remove or overwrite internal planning artifacts unless explicitly asked.
- Preserve concurrent user or teammate changes outside the files you have been asked to own.
- When release scope changes materially, update status and roadmap docs alongside any landing-page copy that depends on them.

## Verification Commands

```powershell
uv sync --extra dev --extra all
uv run --extra dev pytest
uv run --extra dev ruff check .
uv run --extra dev mypy src tests
Set-Location web
npm ci
npm test
npm run build
npm run audit:prod
Set-Location ..
```
