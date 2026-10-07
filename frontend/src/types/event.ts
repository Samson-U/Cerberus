export interface CanonicalEvent {
  event_id: string;
  timestamp: string;
  event_type: string;
  event_category: string;
  source_system: string;
  source_log: string;
  user_id?: string | null;
  device_id?: string | null;
  src_ip?: string | null;
  dst_ip?: string | null;
  correlation_id?: string | null;
  related_entities: string[];
  metadata: Record<string, unknown>;
  severity: string;
  confidence: number;
  description?: string;
}

export interface TimelineEntry extends CanonicalEvent {
  event: string;
  stage?: string;
  stages?: string[];
}
