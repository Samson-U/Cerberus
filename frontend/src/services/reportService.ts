import { request, encodePath } from "./apiClient";
import type { Report } from "../types/report";

interface ApiReport {
  id: string;
  investigation_id: string;
  title: string;
  attack_type: string;
  severity: string;
  confidence: number;
  risk_score: number;
  status: "Generating" | "Final" | "Failed";
  created_at: string;
  executive_summary: string;
  overall_analysis: string;
  timeline: Report["timeline"];
  entities: Report["entities"];
  evidence: Report["evidence"];
  ai_assessment: string;
  recommendations: string[];
  evidence_references: string[];
}

const adapt = (report: ApiReport): Report => ({
  id: report.id,
  investigationId: report.investigation_id,
  title: report.title,
  attackType: report.attack_type,
  severity: report.severity,
  confidence: report.confidence,
  riskScore: report.risk_score,
  status: report.status,
  createdAt: report.created_at,
  executiveSummary: report.executive_summary,
  overallAnalysis: report.overall_analysis,
  timeline: report.timeline,
  entities: report.entities,
  evidence: report.evidence,
  aiAssessment: report.ai_assessment,
  forwardRiskAssessment: report.recommendations.join(" "),
  predictedRisks: [],
  recommendedActions: report.recommendations,
  finalAssessment: report.executive_summary,
});

export const reportService = {
  async getReports(signal?: AbortSignal): Promise<Report[]> {
    const reports = await request<ApiReport[]>("/reports", { signal });
    return reports.map(adapt);
  },
  async generateReport(investigationId: string): Promise<Report> {
    const result = await request<ApiReport>(`/investigations/${encodePath(investigationId)}/generate-report`, { method: "POST" });
    return adapt(result);
  },
};
