import type { CanonicalEvent } from "./event";
import type { Entity } from "./entity";
import type { Evidence } from "./evidence";

export interface Report {
  id: string;
  investigationId: string;
  title: string;
  attackType: string;
  severity: string;
  confidence: number;
  riskScore?: number;
  status: "Generating" | "Final" | "Failed";
  createdAt: string;
  executiveSummary: string;
  overallAnalysis: string;
  timeline: CanonicalEvent[];
  entities: Entity[];
  evidence: Evidence[];
  aiAssessment: string;
  forwardRiskAssessment: string;
  predictedRisks: string[];
  recommendedActions: string[];
  finalAssessment: string;
}
