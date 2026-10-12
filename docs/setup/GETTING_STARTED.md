# 安装与配置

[返回项目首页](../../README.md) · [文档目录](../README.md)

## 环境要求

| 依赖 | 要求 | 用途 |
| --- | --- | --- |
| Python | 3.12（后端限制为 `>=3.12,<3.13`） | 后端与内置探测模块 |
| uv | 可用的稳定版本 | Python 环境与锁定依赖安装 |
| Node.js | 建议 24 LTS；使用 22 时需 22.12+ | Vite 开发服务与构建 |
| pnpm | 10；可使用 `npm install -g pnpm@10.33.0` 安装 | 前端依赖管理 |
| 安全工具 | 按需安装，见下文 | 真实侦察与定向扫描 |

后端和前端分别使用 `backend/uv.lock`、`frontend/pnpm-lock.yaml`。不要混用 npm 或 Yarn 生成另一套前端锁文件。

## 启动前后端

先克隆仓库并进入项目根目录。默认端口无需配置文件，也不要求模型密钥。

终端一：

```bash
cd backend
uv sync --frozen
uv run uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

终端二：

```bash
cd frontend
pnpm install --frozen-lockfile
pnpm dev
```

访问控制台 <http://127.0.0.1:5173>，API 文档 <http://127.0.0.1:8000/docs>，健康检查 <http://127.0.0.1:8000/health>。

### Windows 一键启动

在项目根目录的 PowerShell 中执行：

```powershell
.\start-dev.ps1
```

脚本要求 `uv` 和 `pnpm` 已在 PATH 中可用，会安装所需项目依赖，并打开两个 Windows PowerShell 窗口。`scripts/init_env/setup.ps1` 仅初始化依赖，不启动服务。macOS / Linux 请使用上面的双终端命令。

## 模型配置

将根目录 `.env.example` 复制为根目录 `.env`：

```bash
# macOS / Linux
cp .env.example .env
```

```powershell
# Windows PowerShell
Copy-Item .env.example .env
```

编辑 `.env`：

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `OPENAI_API_KEY` | 空 | 留空使用规则策略与模板摘要，不调用模型 |
| `OPENAI_MODEL` | `gpt-5.4` | 按服务端实际支持和账号权限设置 |
| `OPENAI_BASE_URL` | `https://api.openai.com/v1` | 可改为受信任的 OpenAI 兼容服务地址 |
| `OPENAI_WIRE_API` | `chat_completions` | 选择 `chat_completions` 或 `responses` |
| `LLM_REASONING_EFFORT` | `low` | Responses 请求中的推理强度；需模型支持 |
| `APP_NAME` | `LLM Penetration Testing System` | API 应用名称 |
| `APP_ENV` | `development` | 健康检查展示的环境名称 |

Chat Completions 接入使用流式响应，服务端需支持 `stream` 与 `stream_options`。请求或结构化策略解析失败时会回退到规则逻辑；**任务完成不等于模型调用成功**。修改配置后重启后端。

不要把真实密钥放进示例文件。启用模型前确认服务地址：目标、侦察证据及发现摘要可能发送到该服务。

## 前端配置与端口

默认 API 地址为 `http://127.0.0.1:8000`。

- **手动启动：** 将 `frontend/.env.example` 复制为 `frontend/.env.local`，修改 `VITE_API_BASE_URL`。Vite 默认不读取项目根目录 `.env`。
- **Windows 一键启动：** 根目录 `.env` 中的 `API_HOST`、`API_PORT`、`FRONTEND_PORT` 和 `VITE_API_BASE_URL` 由 `start-dev.ps1` 读取；脚本将 API 地址传给 Vite。
- **手动修改后端端口：** 使用 Uvicorn 的 `--host` / `--port` 参数。仅修改根目录 `API_PORT` 不会改变手动启动的 Uvicorn 监听端口。
- **修改前端端口：** 同步检查 `backend/app/main.py` 中的 CORS 列表；默认仅允许 `http://127.0.0.1:5173` 和 `http://localhost:5173`。

建议保留默认回环地址和端口，不使用 `0.0.0.0` 对外开放开发服务。

## 外部安全工具

| 工具 | 安装来源 | 对应适配器 |
| --- | --- | --- |
| Nmap | [nmap.org](https://nmap.org/download.html) | `nmap`、`heartbleed_probe`（使用 `ssl-heartbleed` NSE 脚本） |
| ProjectDiscovery httpx | [官方安装说明](https://docs.projectdiscovery.io/tools/httpx/install) | `httpx` |
| Nuclei | [官方安装说明](https://docs.projectdiscovery.io/tools/nuclei/install) | `nuclei` |

安装后确认二进制位于 PATH 中。Windows 也会搜索适配器定义的常见安装目录。

**ProjectDiscovery httpx 是 Go 命令行工具，与后端依赖的 Python `httpx` 库不是同一个项目。** 若 PATH 中存在同名 Python CLI，命令解析成功也不代表安装了正确的扫描工具。

`web_fingerprint` 和大部分自定义扫描适配器使用当前 Python 解释器运行内置模块。外部工具不可用时，对应适配器生成 `simulated` 结果；这不构成全局离线模式。Nuclei 默认只加载 `backend/app/assets/nuclei/local-http-fingerprint.yaml`。

本项目不自动创建 Vulhub 等靶场。使用前应自行准备隔离、已授权的目标。

## 开发验证

后端目录中执行：

```bash
uv sync --frozen
uv run pytest -q -k "not test_tool_resolution_for_known_binaries"
```

这是排除本机外部二进制检查的测试子集，不代表完整工具链验证。安装外部工具后运行全部测试：

```bash
uv run pytest -q
```

`test_tool_resolution_for_known_binaries` 直接断言工具可解析，缺少 Nmap、ProjectDiscovery httpx 或 Nuclei 时会失败。该测试检查路径解析，不验证外部工具版本或真实检测能力。

测试使用规则策略，不需要模型密钥。API 与工作流测试会写入项目 `data/`，并可能向 `127.0.0.1` 的 7777、8888、9999 等测试端口发起请求；请在独立工作副本中运行，避免这些端口上有无关服务。不要把测试产生的发现当作靶场验证结果。

前端目录中执行：

```bash
pnpm install --frozen-lockfile
pnpm build
```

构建运行 TypeScript 检查并生成 `frontend/dist/`。`dist/`、`*.tsbuildinfo` 和运行数据均由 Git 忽略。Windows 启动脚本应在 Windows 环境单独验证。

## 常见问题

- **控制台连不上后端：** 先打开 `/health`，再核对前端 API 地址、实际后端端口与 CORS 配置。
- **没有模型密钥也出现分析文字：** 来自规则回退逻辑，不代表调用了真实模型。
- **没有安装安全工具却出现发现：** 查看 `execution_mode`。模拟输出也可能进入验证与报告流程，必须与真实执行区分。
- **报告还不可用：** 报告在 `REPORTING` 阶段生成；此前报告接口返回 404。
- **API 暂时不响应：** 耗时的阶段执行持有全局锁，任务查询可能等待。此实现适合单机原型，不适合高并发服务。
- **重启后任务没有继续运行：** JSON 保存任务状态，但没有自动恢复后台线程；请新建任务重试，保留旧任务供排查。
