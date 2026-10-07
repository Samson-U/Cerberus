import { request } from "./apiClient";
import type { BackendSettings } from "../types/settings";

export const settingsService = {
  getSettings: (signal?: AbortSignal) => request<BackendSettings>("/settings", { signal }),
};
