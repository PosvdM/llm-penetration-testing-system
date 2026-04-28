export type TaskStatus =
  | "PENDING"
  | "RECON"
  | "ANALYSIS"
  | "SCAN"
  | "VERIFY"
  | "POST_VERIFY"
  | "REPORTING"
  | "COMPLETED"
  | "FAILED";

export interface TaskSummary {
  task_id: string;
  target: string;
  scenario: string;
  status: TaskStatus;
  current_phase: string;
  is_running: boolean;
  created_at: string;
}

export interface LLMStrategyPlan {
  summary: string;
  priority: "low" | "medium" | "high";
  recommended_tools: string[];
  focus_areas: string[];
  priority_paths: string[];
  verification_goals: string[];
  stop_conditions: string[];
  rationale: string;
}

export interface TimelineEvent {
  event_id: string;
  title: string;
  status: "done" | "active" | "pending";
  phase: TaskStatus;
  detail: string;
  created_at: string;
}

export interface VerifiedFinding {
  finding_id: string;
  title: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  source_tool: string;
  affected_asset: string | null;
  confidence: "low" | "medium" | "high";
  summary: string;
  impact: string | null;
  evidence: string[];
  artifact_paths: string[];
  remediation: string;
  next_steps: string[];
  verification_status: "verified" | "informational" | "rejected";
}

export interface ReportArtifact {
  report_id: string;
  title: string;
  summary: string;
  report_path: string;
  generated_at: string;
}

export interface ToolExecutionPlan {
  tool_name: string;
  category: string;
  command: string;
  rationale: string;
  target: string;
  available: boolean;
  execution_mode: "native" | "simulated";
}

export interface ToolExecutionResult {
  tool_name: string;
  category: string;
  target: string;
  summary: string;
  evidence: string[];
  success: boolean;
  command: string;
  available: boolean;
  execution_mode: "native" | "simulated";
  raw_output_path: string | null;
  exit_code: number | null;
  duration_ms: number | null;
}

export interface TaskDetail extends TaskSummary {
  created_at: string;
  updated_at: string;
  progress_current: number;
  progress_total: number;
  timeline: TimelineEvent[];
  planned_tools: ToolExecutionPlan[];
  tool_results: ToolExecutionResult[];
  analysis_summary: string | null;
  llm_strategy_plan: LLMStrategyPlan | null;
  verification_summary: string | null;
  verified_findings: VerifiedFinding[];
  report_artifact: ReportArtifact | null;
  latest_result: ToolExecutionResult | null;
  last_error: string | null;
}

export interface TaskCreateRequest {
  target: string;
  scenario: string;
}

export interface TaskAdvanceResponse {
  task: TaskDetail;
  advanced: boolean;
}

export interface TaskStartResponse {
  task: TaskDetail;
  started: boolean;
}

export interface ReportPreviewResponse {
  task_id: string;
  report_path: string;
  content: string;
}
