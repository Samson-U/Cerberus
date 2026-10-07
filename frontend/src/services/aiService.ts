import { request, encodePath } from "./apiClient";
import type { AIAnalysis } from "../types/ai";

interface AIAnalysisResponse {
  summary: string;
  why_suspicious: string[];
  recommendations: string[];
  evidence_references: string[];
  provider?: string;
}

export const aiService = {
  async getAIAnalysis(investigationId: string, signal?: AbortSignal): Promise<AIAnalysis> {
    const result = await request<AIAnalysisResponse>(
      `/investigations/${encodePath(investigationId)}/ai-analysis`,
      { method: "POST", signal },
    );
    return {
      investigationId,
      summary: result.summary,
      whySuspicious: result.why_suspicious,
      recommendations: result.recommendations,
      evidenceReferences: result.evidence_references,
      provider: result.provider,
    };
  },
};
