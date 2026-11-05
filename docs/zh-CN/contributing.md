# 贡献指南

[English original](../../CONTRIBUTING.md)

## 范围

AI Data Access Gateway 当前以 V1 MVP 形式发布。贡献应优先选择范围清晰、易于评审的改动，而不是大面积、带有推测性的重构。凡是会实质影响对外发布行为或文档表述的变更，都应明确说明当前实现边界。

## 前置条件

- Python 3.12+
- Node.js 20+
- `uv`
- `npm`

## 本地环境准备

### 后端

```powershell
uv sync --extra dev --extra all
```

### 前端

```powershell
Set-Location web
npm ci
Set-Location ..
```

## 验证

在提交 Pull Request 之前，请先运行与你改动范围相对应的验证命令。

### 后端

```powershell
uv run --extra dev pytest
uv run --extra dev ruff check .
uv run --extra dev mypy src tests
```

### 前端

```powershell
Set-Location web
npm test
npm run build
npm run audit:prod
Set-Location ..
```

## 远端

我们自己的分支要同时推到下面两个远端。只更新其中一个不算推送完成。`main` 和每条功能分支都按这条执行。

- GitLab：`git@gitlab.yeahmobi.com:gst/AI-Data-Access-Gateway.git`
- GitHub：`git@github.com:zhulaoqi/AI-Data-Access-Gateway.git`

`upstream`（`HanZephyr/AI-Data-Access-Gateway`）是公开上游。没有人明确要求时，不要把我们的分支推上去。

`origin` 只指向 GitHub。分支如果跟踪 `origin`，直接 `git push` 会漏掉 GitLab。改为跟踪 `gitlab`。这个远端配置了两个推送地址，一次推送会同时更新两边。

每个克隆配置一次。第一条 `--add --push` 会替换掉隐式的推送地址，所以两个地址都要加上：

```bash
git remote add gitlab git@gitlab.yeahmobi.com:gst/AI-Data-Access-Gateway.git
git remote set-url --add --push gitlab git@gitlab.yeahmobi.com:gst/AI-Data-Access-Gateway.git
git remote set-url --add --push gitlab git@github.com:zhulaoqi/AI-Data-Access-Gateway.git
git push -u gitlab HEAD
```

新分支第一次推送前，用 `git remote get-url --push --all gitlab` 确认列出了两个地址。之后在这条分支上 `git push` 会同时更新 GitLab 和 GitHub。

## Pull Request 期望

- 保持改动聚焦，避免无关清理混入
- 行为变化时同步补齐或更新测试
- 面向发布的英文与中文文档变更应保持同步
- 不要声称仓库尚未实现的能力
- 保留工作树中与本次任务无关的用户或队友改动
- 如果改动影响安全、Schema 或 API 表面，请在 Pull Request 描述中明确说明

## 开发说明

- 以当前代码、测试与可运行配置作为事实来源。
- 历史设计文档可以提供上下文，但不能覆盖已经实现的行为。
- 如果确实需要做较大的改动，尽量拆分为顺序明确的多个 Pull Request，以便评审和回滚。
