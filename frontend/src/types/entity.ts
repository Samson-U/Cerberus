export interface Entity {
  entity_id: string;
  entity_type: string;
  name: string;
  context: string;
  risk: string;
  related_event_ids: string[];
  attributes?: Record<string, unknown>;
}
