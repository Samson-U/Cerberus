export interface AIAnalysis {
  investigationId: string;
  summary: string;
  whySuspicious: string[];
  recommendations: string[];
  evidenceReferences: string[];
  attackProgression?: string[];
  provider?: string;
}
