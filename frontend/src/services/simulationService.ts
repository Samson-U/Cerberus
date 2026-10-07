import type {
  LiveEventItems,
  LiveIncidentItems,
  SimulationScenario,
  SimulationStatus,
} from "../types/simulation";
import { request } from "./apiClient";

export const simulationService = {
  start: (options: {
    demo_mode?: boolean;
    scenario?: SimulationScenario;
    interval_seconds?: number;
  } = {}) =>
    request<SimulationStatus>("/simulation/start", {
      method: "POST",
      body: JSON.stringify(options),
    }),
  stop: () =>
    request<SimulationStatus>("/simulation/stop", { method: "POST" }),
  reset: () =>
    request<SimulationStatus>("/simulation/reset", { method: "POST" }),
  getStatus: (signal?: AbortSignal) =>
    request<SimulationStatus>("/simulation/status", { signal }),
  getLiveEvents: (limit = 50, signal?: AbortSignal) =>
    request<LiveEventItems>(`/events/live?limit=${limit}`, { signal }),
  getLiveIncidents: (limit = 50, signal?: AbortSignal) =>
    request<LiveIncidentItems>(`/incidents/live?limit=${limit}`, { signal }),
};
