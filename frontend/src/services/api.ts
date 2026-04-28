import type {
  ReportPreviewResponse,
  TaskAdvanceResponse,
  TaskCreateRequest,
  TaskDetail,
  TaskStartResponse,
  TaskSummary,
} from "../types/task";

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL?.replace(/\/$/, "") ?? "http://127.0.0.1:8000";

export interface HealthResponse {
  status: string;
  app_name: string;
  environment: string;
}

export async function fetchHealth(): Promise<HealthResponse> {
  const response = await fetch(`${API_BASE_URL}/health`);
  if (!response.ok) {
    throw new Error("Failed to fetch backend health.");
  }

  return response.json() as Promise<HealthResponse>;
}

export async function fetchTasks(): Promise<TaskSummary[]> {
  const response = await fetch(`${API_BASE_URL}/api/tasks`);
  if (!response.ok) {
    throw new Error("Failed to fetch tasks.");
  }

  return response.json() as Promise<TaskSummary[]>;
}

export async function fetchTaskDetail(taskId: string): Promise<TaskDetail> {
  const response = await fetch(`${API_BASE_URL}/api/tasks/${taskId}`);
  if (!response.ok) {
    throw new Error("Failed to fetch task detail.");
  }

  return response.json() as Promise<TaskDetail>;
}

export async function createTask(payload: TaskCreateRequest): Promise<TaskDetail> {
  const response = await fetch(`${API_BASE_URL}/api/tasks`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    throw new Error("Failed to create task.");
  }

  return response.json() as Promise<TaskDetail>;
}

export async function advanceTask(taskId: string): Promise<TaskAdvanceResponse> {
  const response = await fetch(`${API_BASE_URL}/api/tasks/${taskId}/advance`, {
    method: "POST",
  });
  if (!response.ok) {
    throw new Error("Failed to advance task.");
  }

  return response.json() as Promise<TaskAdvanceResponse>;
}

export async function startTask(taskId: string): Promise<TaskStartResponse> {
  const response = await fetch(`${API_BASE_URL}/api/tasks/${taskId}/start`, {
    method: "POST",
  });
  if (!response.ok) {
    throw new Error("Failed to start task.");
  }

  return response.json() as Promise<TaskStartResponse>;
}

export async function fetchTaskReport(taskId: string): Promise<ReportPreviewResponse> {
  const response = await fetch(`${API_BASE_URL}/api/tasks/${taskId}/report`);
  if (!response.ok) {
    throw new Error("Failed to fetch task report.");
  }

  return response.json() as Promise<ReportPreviewResponse>;
}
