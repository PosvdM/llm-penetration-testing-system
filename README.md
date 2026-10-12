# LLM Penetration Testing System

**基于大语言模型的自动化渗透测试原型**：面向授权靶场、教学与安全竞赛，将目标侦察、LLM 策略分析、工具执行、证据验证和报告生成串成可查看的工作流。

前端使用 React + TypeScript，后端使用 Python + FastAPI。LLM 负责生成结构化扫描策略与文字摘要；工具适配器负责执行探测，规则模块负责整理验证结论。

[快速开始](docs/setup/GETTING_STARTED.md) · [演示指南](docs/demo/WALKTHROUGH.md) · [架构与源码导航](docs/architecture/OVERVIEW.md) · [文档目录](docs/README.md)

> 仅对自己拥有或明确获得授权的目标使用。系统没有身份认证、目标授权校验或执行沙箱，请仅在受控本地环境运行，不要将 API 暴露到公网。工具缺失时的模拟结果不能作为真实漏洞证据。

## 功能概览

| 能力 | 实现内容 |
| --- | --- |
| 任务管理 | 创建目标任务、手动推进阶段、后台自动运行、保存任务状态与时间线 |
| 目标侦察 | 使用 Nmap、ProjectDiscovery httpx 和内置 Web 指纹模块收集服务与应用信息 |
| LLM 策略分析 | 输出推荐工具、关注点、重点路径、验证目标及停止条件；对模型输出进行结构校验、工具过滤和路径规范化 |
| 扫描编排 | 按策略选择扫描适配器，传入重点路径等上下文，统一记录执行结果、超时与原始输出 |
| 证据验证 | 整理风险等级、置信度、验证状态、修复建议和原始产物路径 |
| 报告展示 | 生成 Markdown 报告，在前端查看任务时间线、策略、工具结果和报告预览 |

### 工作流程

```mermaid
flowchart LR
    A[创建任务] --> B[目标侦察]
    B --> C[LLM 策略分析]
    C --> D[工具扫描]
    D --> E[规则验证]
    E --> F[证据整理阶段]
    F --> G[报告生成]
    G --> H[完成]
```

自动运行沿固定状态机推进。LLM 策略影响工具选择和扫描参数；验证目标与停止条件会形成评估建议，但系统没有多轮自主重规划循环。

### 工具覆盖

默认注册 **3 个侦察适配器、8 个扫描适配器**，不代表 11 个独立外部工具：

- **侦察：** `nmap`、`httpx`、`web_fingerprint`。
- **扫描：** `path_probe`、`input_surface`、`param_injection_probe`、`command_probe`、`login_sqli_probe`、`sensitive_file_probe`、`heartbleed_probe`、`nuclei`。
- 自定义模块覆盖路径与输入面发现、参数注入信号、命令执行信号、登录 SQL 注入、敏感文件暴露等定向检查。Heartbleed 检查调用 Nmap；Nuclei 默认使用仓库中的本地 HTTP 指纹模板，不能等同于完整漏洞模板库扫描。

具体入口见[工具适配器与执行边界](docs/architecture/OVERVIEW.md#工具适配器与执行边界)。

## 快速开始

需要 **Python 3.12、uv、Node.js 22.12+（建议 Node.js 24 LTS）、pnpm 10**。安全工具按需单独安装。

```bash
git clone https://github.com/PosvdM/llm-penetration-testing-system.git
cd llm-penetration-testing-system
```

在两个终端中分别运行：

**后端**

```bash
cd backend
uv sync --frozen
uv run uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

**前端**

```bash
cd frontend
pnpm install --frozen-lockfile
pnpm dev
```

- 控制台：<http://127.0.0.1:5173>
- API 文档：<http://127.0.0.1:8000/docs>
- Windows 可在项目根目录运行 `./start-dev.ps1`，分别打开前后端 PowerShell 窗口。

**不配置模型密钥也能启动**，此时使用规则策略和模板摘要。若要启用 LLM，将根目录 `.env.example` 复制为 `.env`，设置密钥、模型与服务地址。配置步骤、外部工具依赖和常见问题见[快速开始文档](docs/setup/GETTING_STARTED.md)。

启动服务只展示控制台，不会自动启动扫描；点击任务运行后，内置探测模块仍可能发起真实网络请求。首次使用请遵循[演示指南](docs/demo/WALKTHROUGH.md)。

## 项目结构

```text
.
├── backend/                 # FastAPI、任务编排、LLM 服务、工具适配器与测试
├── frontend/                # React 控制台、API 客户端与类型定义
├── data/                    # 本地任务、原始日志与报告（运行产物不提交）
├── docs/
│   ├── architecture/        # 架构、模块职责、API 与扩展入口
│   ├── setup/               # 安装、配置与开发验证
│   ├── demo/                # 演示步骤与结果判读
│   ├── references/          # 竞赛参考材料
│   └── archive/             # 早期规划与环境记录，不代表当前功能
├── scripts/                 # 环境初始化脚本
├── .env.example             # 后端及 Windows 启动脚本配置示例
└── start-dev.ps1             # Windows 双终端启动入口
```

## 开发验证

```bash
# backend/：不要求安装外部安全工具的测试子集
uv run pytest -q -k "not test_tool_resolution_for_known_binaries"

# frontend/：TypeScript 检查与生产构建
pnpm build
```

完整后端测试命令为 `uv run pytest -q`。其中 `test_tool_resolution_for_known_binaries` 要求本机可解析 Nmap、ProjectDiscovery httpx 和 Nuclei；未安装时该项会失败。测试也会写入本地 `data/`，工作流测试可能请求回环地址，不是完全隔离的单元测试。详见[开发验证说明](docs/setup/GETTING_STARTED.md#开发验证)。

## 使用边界

- **工程原型：** 后台线程与进程内全局锁驱动任务，本地 JSON 保存状态；不支持分布式调度、多用户隔离或中断任务自动恢复。
- **真实与模拟执行可能混用：** 缺少外部工具时使用模拟输出；有 Python 环境的内置模块仍可真实执行。查看每次结果的 `execution_mode`，含模拟输入的报告不能作为实测结论。
- **验证规则有覆盖范围：** `verified` 也可能表示已确认的攻击面或暴露信息，不必然表示可利用漏洞；没有发现不代表目标安全。
- **LLM 是可选依赖：** 支持 OpenAI 兼容的 Responses / Chat Completions 协议；没有独立 Anthropic SDK 接入、RAG 或多智能体协作实现。
- **敏感数据：** 启用 LLM 后会向所配置服务发送目标信息、扫描证据或发现摘要。请先确认授权与数据处理要求，不要提交 `.env`、扫描日志或未脱敏报告。
