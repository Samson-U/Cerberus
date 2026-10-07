export interface BackendSettings {
  api_available: boolean;
  ollama_available: boolean;
  data_sources: Record<string, string | null>;
}
