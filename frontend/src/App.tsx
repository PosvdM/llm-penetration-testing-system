import { FormEvent, useEffect, useState } from "react";

import {
  advanceTask,
  createTask,
  fetchTaskReport,
  fetchHealth,
  fetchTaskDetail,
  fetchTasks,
  startTask,
  type HealthResponse,
} from "./services/api";
import { MarkdownPreview } from "./components/MarkdownPreview";
import type { TaskCreateRequest, TaskDetail, TaskSummary } from "./types/task";

const phaseCards = [
  {
    title: "Recon 侦察",
    description: "识别目标指纹、枚举服务，并快速梳理当前可见攻击面。",
  },
  {
    title: "LLM 分析",
    description: "把原始信号转成测试假设、扫描重点与执行决策。",
  },
  {
    title: "Verification 验证",
    description: "区分命中、已验证和应停止继续测试的情况，减少误报。",
  },
  {
    title: "Report 报告",
    description: "自动汇总时间线、证据路径、修复建议与结构化输出。",
  },
];

const defaultForm: TaskCreateRequest = {
  target: "http://127.0.0.1:8080",
  scenario: "Vulhub / Struts2 S2-045 演示场景",
};

const displayModelGroups = [
  {
    vendor: "GPT",
    models: ["GPT-5.4", "GPT-5.4-mini", "GPT-5", "GPT-4.1"],
  },
  {
    vendor: "Claude",
    models: ["Claude Sonnet 4.5", "Claude Opus 4.1", "Claude Haiku 4.5"],
  },
  {
    vendor: "Gemini",
    models: ["Gemini 2.5 Pro", "Gemini 2.5 Flash", "Gemini 2.0 Flash"],
  },
] as const;

const statusLabels: Record<string, string> = {
  PENDING: "等待开始",
  RECON: "Recon 侦察中",
  ANALYSIS: "LLM 策略分析",
  SCAN: "执行扫描工具",
  VERIFY: "验证发现",
  POST_VERIFY: "证据整理",
  REPORTING: "生成结构化报告",
  COMPLETED: "流程已完成",
  FAILED: "执行失败",
};

const selectedTaskStorageKey = "llm-pentest-selected-task";

function formatTaskStatus(status: string): string {
  return statusLabels[status] ?? status;
}

function sortTasksNewestFirst(tasks: TaskSummary[]): TaskSummary[] {
  return [...tasks].sort((left, right) => {
    return new Date(right.created_at).getTime() - new Date(left.created_at).getTime();
  });
}

function formatTaskTime(isoTime: string): string {
  const date = new Date(isoTime);
  if (Number.isNaN(date.getTime())) {
    return isoTime;
  }
  return date.toLocaleString("zh-CN", {
    hour12: false,
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function getStoredTaskId(): string | null {
  return window.localStorage.getItem(selectedTaskStorageKey);
}

function storeTaskId(taskId: string | null): void {
  if (taskId) {
    window.localStorage.setItem(selectedTaskStorageKey, taskId);
    return;
  }
  window.localStorage.removeItem(selectedTaskStorageKey);
}

export default function App() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [tasks, setTasks] = useState<TaskSummary[]>([]);
  const [selectedTask, setSelectedTask] = useState<TaskDetail | null>(null);
  const [form, setForm] = useState<TaskCreateRequest>(defaultForm);
  const [selectedDisplayModel, setSelectedDisplayModel] = useState("GPT-5.4");
  const [error, setError] = useState<string>("");
  const [reportContent, setReportContent] = useState<string>("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isAdvancing, setIsAdvancing] = useState(false);
  const [isStarting, setIsStarting] = useState(false);
  const [isRefreshingReport, setIsRefreshingReport] = useState(false);

  async function loadTasks(preferredTaskId?: string) {
    const [healthPayload, tasksPayload] = await Promise.all([fetchHealth(), fetchTasks()]);
    const orderedTasks = sortTasksNewestFirst(tasksPayload);

    setHealth(healthPayload);
    setTasks(orderedTasks);

    const storedTaskId = getStoredTaskId();
    const nextTaskId =
      preferredTaskId ??
      storedTaskId ??
      selectedTask?.task_id ??
      orderedTasks[0]?.task_id;

    if (nextTaskId) {
      const detail = await fetchTaskDetail(nextTaskId);
      setSelectedTask(detail);
      storeTaskId(detail.task_id);
      if (detail.report_artifact) {
        const report = await fetchTaskReport(nextTaskId);
        setReportContent(report.content);
      } else {
        setReportContent("");
      }
    } else {
      setSelectedTask(null);
      setReportContent("");
      storeTaskId(null);
    }
  }

  useEffect(() => {
    let cancelled = false;

    async function loadDashboard() {
      try {
        await loadTasks();
      } catch (loadError) {
        if (!cancelled) {
          setError(loadError instanceof Error ? loadError.message : "Unknown error");
        }
      }
    }

    void loadDashboard();

    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!selectedTask?.is_running) {
      return;
    }

    const intervalId = window.setInterval(() => {
      void handleSelectTask(selectedTask.task_id, false);
    }, 800);

    return () => {
      window.clearInterval(intervalId);
    };
  }, [selectedTask?.is_running, selectedTask?.task_id]);

  async function handleCreateTask(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setIsSubmitting(true);
    setError("");

    try {
      const created = await createTask(form);
      await loadTasks(created.task_id);
      setForm(defaultForm);
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : "Failed to create task.");
    } finally {
      setIsSubmitting(false);
    }
  }

  async function handleSelectTask(taskId: string, clearError = true) {
    try {
      if (clearError) {
        setError("");
      }
      const [detail, refreshedTasks] = await Promise.all([fetchTaskDetail(taskId), fetchTasks()]);
      setSelectedTask(detail);
      setTasks(sortTasksNewestFirst(refreshedTasks));
      storeTaskId(taskId);
      if (detail.report_artifact) {
        const report = await fetchTaskReport(taskId);
        setReportContent(report.content);
      } else {
        setReportContent("");
      }
    } catch (detailError) {
      setError(detailError instanceof Error ? detailError.message : "Failed to load task.");
    }
  }

  async function handleAdvanceTask() {
    if (!selectedTask) {
      return;
    }

    setIsAdvancing(true);
    setError("");

    try {
      const response = await advanceTask(selectedTask.task_id);
      setSelectedTask(response.task);
      storeTaskId(response.task.task_id);
      const refreshedTasks = await fetchTasks();
      setTasks(sortTasksNewestFirst(refreshedTasks));
      if (response.task.report_artifact) {
        const report = await fetchTaskReport(response.task.task_id);
        setReportContent(report.content);
      }
    } catch (advanceError) {
      setError(advanceError instanceof Error ? advanceError.message : "Failed to advance task.");
    } finally {
      setIsAdvancing(false);
    }
  }

  async function handleStartTask() {
    if (!selectedTask) {
      return;
    }

    setIsStarting(true);
    setError("");

    try {
      const response = await startTask(selectedTask.task_id);
      setSelectedTask(response.task);
      storeTaskId(response.task.task_id);
      const refreshedTasks = await fetchTasks();
      setTasks(sortTasksNewestFirst(refreshedTasks));
      if (response.task.report_artifact) {
        const report = await fetchTaskReport(response.task.task_id);
        setReportContent(report.content);
      }
    } catch (startError) {
      setError(startError instanceof Error ? startError.message : "Failed to start task.");
    } finally {
      setIsStarting(false);
    }
  }

  async function handleRefreshReport() {
    if (!selectedTask?.report_artifact) {
      return;
    }

    setIsRefreshingReport(true);
    setError("");

    try {
      const report = await fetchTaskReport(selectedTask.task_id);
      setReportContent(report.content);
    } catch (reportError) {
      setError(reportError instanceof Error ? reportError.message : "Failed to refresh report.");
    } finally {
      setIsRefreshingReport(false);
    }
  }

  return (
    <main className="page-shell">
      <section className="hero">
        <div className="hero-copy">
          <p className="eyebrow">Authorized Lab Workflow</p>
          <h1>基于 LLM 的自动化渗透测试系统</h1>
          <p className="hero-text">
            面向竞赛演示的自动化安全测试平台，覆盖目标分析、工具编排、证据留痕、
            Verification 结论与结构化报告输出。
          </p>
        </div>
        <div className="status-card">
          <span className="status-label">后端状态</span>
          <strong>{health ? `${health.status} / ${health.environment}` : "连接中..."}</strong>
          <span className="status-hint">
            {health ? health.app_name : error || "请先启动 FastAPI 后端以启用实时数据。"}
          </span>
        </div>
      </section>

      <section className="panel-grid">
        {phaseCards.map((card) => (
          <article className="panel" key={card.title}>
            <h2>{card.title}</h2>
            <p>{card.description}</p>
          </article>
        ))}
      </section>

      <section className="workspace-grid">
        <section className="composer panel">
          <div className="section-heading">
            <h2>创建任务</h2>
            <p>登记授权靶场目标，并创建新的自动化测试实例。</p>
          </div>

          <form className="task-form" onSubmit={handleCreateTask}>
            <label>
              <span>目标</span>
              <input
                value={form.target}
                onChange={(event) => setForm((current) => ({ ...current, target: event.target.value }))}
                placeholder="http://127.0.0.1:8080"
              />
            </label>
            <label>
              <span>场景</span>
              <input
                value={form.scenario}
                onChange={(event) =>
                  setForm((current) => ({ ...current, scenario: event.target.value }))
                }
                placeholder="Vulhub / Struts2 S2-045 演示场景"
              />
            </label>
            <label>
              <span>Model</span>
              <select
                value={selectedDisplayModel}
                onChange={(event) => setSelectedDisplayModel(event.target.value)}
              >
                {displayModelGroups.map((group) => (
                  <optgroup key={group.vendor} label={group.vendor}>
                    {group.models.map((model) => (
                      <option key={model} value={model}>
                        {model}
                      </option>
                    ))}
                  </optgroup>
                ))}
              </select>
            </label>
            <button className="primary-button" disabled={isSubmitting} type="submit">
              {isSubmitting ? "创建中..." : "创建任务"}
            </button>
          </form>

          {error ? <p className="error-text">{error}</p> : null}
        </section>

        <section className="panel">
          <div className="section-heading">
            <h2>任务队列</h2>
            <p>按创建时间倒序显示，刷新页面后默认回到最新或你上次选中的任务。</p>
          </div>

          <div className="task-list compact">
            {tasks.length === 0 ? (
              <div className="task-card muted">当前还没有任务。</div>
            ) : (
              tasks.map((task) => (
                <button
                  className={`task-card task-button ${
                    selectedTask?.task_id === task.task_id ? "task-selected" : ""
                  }`}
                  key={task.task_id}
                  onClick={() => void handleSelectTask(task.task_id)}
                  type="button"
                >
                  <div className="task-card-header">
                    <h3>{task.scenario}</h3>
                    <span className={`badge badge-${task.status.toLowerCase()}`}>{task.status}</span>
                  </div>
                  <p className="task-target">{task.target}</p>
                  <p>{task.current_phase || formatTaskStatus(task.status)}</p>
                  <div className="task-card-footer">
                    <span className="queue-hint">{task.is_running ? "自动运行中" : "空闲"}</span>
                    <span className="task-time">{formatTaskTime(task.created_at)}</span>
                  </div>
                </button>
              ))
            )}
          </div>
        </section>
      </section>

      <section className="task-detail-grid">
        <section className="panel">
          <div className="section-heading">
            <h2>工作流时间线</h2>
            <p>展示状态机推进过程与当前执行说明。</p>
          </div>

          {selectedTask ? (
            <>
              <div className="task-meta">
                <div>
                  <span className="status-label">当前任务</span>
                  <h3>{selectedTask.scenario}</h3>
                </div>
                <div className="progress-chip">
                  步骤 {selectedTask.progress_current} / {selectedTask.progress_total}
                </div>
              </div>
              <p className="task-target">{selectedTask.target}</p>
              <div className="button-row">
                <button
                  className="primary-button"
                  disabled={
                    isStarting ||
                    selectedTask.is_running ||
                    selectedTask.status === "COMPLETED" ||
                    selectedTask.status === "FAILED"
                  }
                  onClick={() => void handleStartTask()}
                  type="button"
                >
                  {isStarting ? "启动中..." : "启动自动流程"}
                </button>
                <button
                  className="secondary-button"
                  disabled={
                    isAdvancing ||
                    selectedTask.is_running ||
                    selectedTask.status === "COMPLETED" ||
                    selectedTask.status === "FAILED"
                  }
                  onClick={() => void handleAdvanceTask()}
                  type="button"
                >
                  {isAdvancing ? "推进中..." : "手动推进一步"}
                </button>
              </div>

              {selectedTask.last_error ? <p className="error-text">{selectedTask.last_error}</p> : null}

              <div className="timeline">
                {selectedTask.timeline.map((event) => (
                  <article className={`timeline-item timeline-${event.status}`} key={event.event_id}>
                    <div className="timeline-dot" />
                    <div className="timeline-content">
                      <div className="timeline-heading">
                        <strong>{event.title}</strong>
                        <span>{formatTaskStatus(event.phase)}</span>
                      </div>
                      <p>{event.detail}</p>
                    </div>
                  </article>
                ))}
              </div>
            </>
          ) : (
            <div className="task-card muted">请选择一个任务查看时间线。</div>
          )}
        </section>

        <section className="panel">
          <div className="section-heading">
            <h2>工具计划与结果</h2>
            <p>展示标准化工具计划、LLM 决策、验证结论与报告产物。</p>
          </div>

          {selectedTask ? (
            <div className="detail-stack">
              {selectedTask.planned_tools.length > 0 ? (
                selectedTask.planned_tools.map((tool) => (
                  <article className="detail-card" key={tool.tool_name}>
                    <div className="task-card-header">
                      <h3>{tool.tool_name}</h3>
                      <span className={`badge ${tool.available ? "badge-completed" : "badge-pending"}`}>
                        {tool.execution_mode}
                      </span>
                    </div>
                    <p>{tool.rationale}</p>
                    <code>{tool.command}</code>
                  </article>
                ))
              ) : (
                <article className="detail-card">
                  <div className="task-card-header">
                    <h3>Scan Plan</h3>
                    <span className="badge badge-pending">none</span>
                  </div>
                  <p>当前没有安排应用层扫描工具，通常表示 LLM 判断目标暂不适合继续深测。</p>
                </article>
              )}

              <article className="detail-card">
                <div className="task-card-header">
                  <h3>LLM 分析</h3>
                  <span className="badge badge-analysis">analysis</span>
                </div>
                {selectedTask.analysis_summary ? (
                  <>
                    <p>{selectedTask.analysis_summary}</p>
                    {selectedTask.llm_strategy_plan ? (
                      <div className="detail-stack nested">
                        <p className="queue-hint">
                          priority: {selectedTask.llm_strategy_plan.priority} | tools:{" "}
                          {selectedTask.llm_strategy_plan.recommended_tools.join(", ") || "none"}
                        </p>
                        <p>{selectedTask.llm_strategy_plan.rationale}</p>
                        {selectedTask.llm_strategy_plan.focus_areas.length > 0 ? (
                          <ul className="evidence-list">
                            {selectedTask.llm_strategy_plan.focus_areas.map((item) => (
                              <li key={item}>focus: {item}</li>
                            ))}
                          </ul>
                        ) : null}
                        {selectedTask.llm_strategy_plan.priority_paths.length > 0 ? (
                          <ul className="evidence-list">
                            {selectedTask.llm_strategy_plan.priority_paths.map((item) => (
                              <li key={item}>path: {item}</li>
                            ))}
                          </ul>
                        ) : null}
                        {selectedTask.llm_strategy_plan.verification_goals.length > 0 ? (
                          <ul className="evidence-list">
                            {selectedTask.llm_strategy_plan.verification_goals.map((item) => (
                              <li key={item}>verify: {item}</li>
                            ))}
                          </ul>
                        ) : null}
                        {selectedTask.llm_strategy_plan.stop_conditions.length > 0 ? (
                          <ul className="evidence-list">
                            {selectedTask.llm_strategy_plan.stop_conditions.map((item) => (
                              <li key={item}>stop: {item}</li>
                            ))}
                          </ul>
                        ) : null}
                      </div>
                    ) : null}
                  </>
                ) : (
                  <p className="muted">进入 ANALYSIS 阶段后，这里会显示 LLM 的总结与下一步建议。</p>
                )}
              </article>

              <article className="detail-card">
                <div className="task-card-header">
                  <h3>验证结论</h3>
                  <span className="badge badge-verify">verify</span>
                </div>
                {selectedTask.verification_summary ? (
                  <>
                    <p>{selectedTask.verification_summary}</p>
                    {selectedTask.verified_findings.length > 0 ? (
                      <div className="detail-stack nested">
                        {selectedTask.verified_findings.map((finding) => (
                          <div className="result-card" key={finding.finding_id}>
                            <div className="task-card-header">
                              <strong>{finding.title}</strong>
                              <span className="badge badge-pending">{finding.severity}</span>
                            </div>
                            <p>{finding.summary}</p>
                            <p className="queue-hint">
                              {finding.source_tool} | {finding.verification_status} | confidence:{" "}
                              {finding.confidence}
                            </p>
                            {finding.affected_asset ? (
                              <p className="queue-hint">asset: {finding.affected_asset}</p>
                            ) : null}
                            {finding.impact ? <p>{finding.impact}</p> : null}
                            <ul className="evidence-list">
                              {finding.evidence.map((item) => (
                                <li key={item}>{item}</li>
                              ))}
                            </ul>
                            <p>{finding.remediation}</p>
                            {finding.next_steps.length > 0 ? (
                              <ul className="evidence-list">
                                {finding.next_steps.map((item) => (
                                  <li key={item}>next: {item}</li>
                                ))}
                              </ul>
                            ) : null}
                            {finding.artifact_paths.length > 0 ? (
                              <div className="detail-stack nested">
                                {finding.artifact_paths.map((item) => (
                                  <code key={item}>{item}</code>
                                ))}
                              </div>
                            ) : null}
                          </div>
                        ))}
                      </div>
                    ) : null}
                  </>
                ) : (
                  <p className="muted">进入 VERIFY 阶段后，这里会显示验证摘要和 findings。</p>
                )}
              </article>

              <article className="detail-card">
                <div className="task-card-header">
                  <h3>报告</h3>
                  <span className="badge badge-reporting">report</span>
                </div>
                {selectedTask.report_artifact ? (
                  <>
                    <p>{selectedTask.report_artifact.summary}</p>
                    <div className="report-meta">
                      <code>{selectedTask.report_artifact.report_path}</code>
                      <button
                        className="secondary-button inline-button"
                        disabled={isRefreshingReport}
                        onClick={() => void handleRefreshReport()}
                        type="button"
                      >
                        {isRefreshingReport ? "刷新中..." : "刷新报告预览"}
                      </button>
                    </div>
                    {reportContent ? (
                      <div className="report-preview">
                        <MarkdownPreview content={reportContent} />
                      </div>
                    ) : null}
                  </>
                ) : (
                  <p className="muted">进入 REPORTING 阶段后，会在本地生成报告文件并显示预览。</p>
                )}
              </article>

              <article className="detail-card">
                <div className="task-card-header">
                  <h3>扫描与侦察结果</h3>
                  <span className="badge badge-recon">{selectedTask.tool_results.length} 项</span>
                </div>
                {selectedTask.tool_results.length > 0 ? (
                  <div className="detail-stack nested">
                    {selectedTask.tool_results.map((result) => (
                      <div className="result-card" key={`${result.tool_name}-${result.summary}`}>
                        <div className="task-card-header">
                          <strong>{result.tool_name}</strong>
                          <span
                            className={`badge ${
                              result.success ? "badge-completed" : "badge-failed"
                            }`}
                          >
                            {result.execution_mode}
                          </span>
                        </div>
                        <p>{result.summary}</p>
                        <p className="queue-hint">
                          退出码: {result.exit_code ?? "n/a"} | 耗时: {result.duration_ms ?? "n/a"} ms
                        </p>
                        <ul className="evidence-list">
                          {result.evidence.map((item) => (
                            <li key={item}>{item}</li>
                          ))}
                        </ul>
                        {result.raw_output_path ? <code>{result.raw_output_path}</code> : null}
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="muted">启动自动流程或进入 Recon 阶段后，这里会显示工具执行结果。</p>
                )}
              </article>
            </div>
          ) : (
            <div className="task-card muted">当前未选择任务。</div>
          )}
        </section>
      </section>
    </main>
  );
}
