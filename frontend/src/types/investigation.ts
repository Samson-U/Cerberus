export interface AttackStage {
  stage_id: string;
  stage: string;
  user_id?: string | null;
  device_id?: string | null;
  start_time: string;
  end_time: string;
  confidence: number;
  evidence: string[];
  file_count?: number;
}

export interface RiskAssessment {
  risk_score: number;
  risk_level: string;
  confidence: number;
  factors?: string[];
}

export interface Recommendation {
  title: string;
  description: string;
  priority?: string;
  evidence_references?: string[];
}

export interface Investigation {
  id: string;
  title: string;
  attack_type: string;
  severity: string;
  risk_score: number;
  status: string;
  confidence: number;
  user_id?: string | null;
  device_id?: string | null;
  user_name?: string;
  device_name?: string;
  start_time: string;
  end_time: string;
  duration: string;
  stages: string[];
  evidence_count: number;
  evidence?: string[];
  stage_records?: AttackStage[];
  entities?: import("./entity").Entity[];
  recommendations?: string[];
  risk_assessment?: RiskAssessment;
}
