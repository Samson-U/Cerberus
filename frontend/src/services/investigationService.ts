import { request, encodePath } from "./apiClient";
import type { Investigation } from "../types/investigation";
import type { TimelineEntry } from "../types/event";
import type { Graph } from "../types/graph";
import type { Entity } from "../types/entity";
import type { CanonicalEvent } from "../types/event";

export type InvestigationListItem = Investigation;

export const investigationService = {
  getInvestigations: (signal?: AbortSignal) => request<InvestigationListItem[]>("/investigations", { signal }),
  getInvestigation: (id: string, signal?: AbortSignal) => request<Investigation>(`/investigations/${encodePath(id)}`, { signal }),
  getTimeline: (id: string, signal?: AbortSignal) => request<{ attack_id: string; timeline: TimelineEntry[] }>(`/investigations/${encodePath(id)}/timeline`, { signal }),
  getEvidence: (id: string, signal?: AbortSignal) => request<CanonicalEvent[]>(`/investigations/${encodePath(id)}/evidence`, { signal }),
  getEntities: (id: string, signal?: AbortSignal) => request<Entity[]>(`/investigations/${encodePath(id)}/entities`, { signal }),
  getGraph: (id: string, signal?: AbortSignal) => request<Graph>(`/investigations/${encodePath(id)}/graph`, { signal }),
  updateStatus: (id: string, status: string) =>
    request<Investigation>(`/investigations/${encodePath(id)}/status`, {
      method: "PATCH",
      body: JSON.stringify({ status }),
    }),
};
