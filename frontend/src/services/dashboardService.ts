import { request } from "./apiClient";
import type { CanonicalEvent } from "../types/event";

export interface DashboardData {
  generated_at: string;
  security_posture: number;
  active_threats: number;
  critical_incidents: number;
  events_processed: number;
  suspicious_entities: number;
  reconstructed_attacks: number;
  recent_events: CanonicalEvent[];
  activity_series: { timestamp: string; count: number }[];
}

export const dashboardService = {
  getDashboard: (signal?: AbortSignal) => request<DashboardData>("/dashboard", { signal }),
};
