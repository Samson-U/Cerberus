import { request } from "./apiClient";
import type { Investigation } from "../types/investigation";

export interface ThreatPage {
  items: Investigation[];
  page: number;
  page_size: number;
  total: number;
}

export const threatService = {
  getActiveThreats: (filters: { search?: string; severity?: string; status?: string; page?: number; page_size?: number } = {}, signal?: AbortSignal) => {
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(filters)) {
      if (value !== undefined && value !== "") query.set(key, String(value));
    }
    const suffix = query.size ? `?${query.toString()}` : "";
    return request<ThreatPage>(`/threats/active${suffix}`, { signal });
  },
};
