import type { CanonicalEvent } from "./event";
import type { Investigation } from "./investigation";

export type SimulationScenario =
  | "INSIDER_THEFT"
  | "MALWARE_INFECTION"
  | "LATERAL_MOVEMENT";

export interface SimulationStatus {
  running: boolean;
  session_id: string | null;
  start_time: string | null;
  demo_mode: boolean;
  demo_scenario: SimulationScenario | null;
  interval_seconds: number;
  events_generated: number;
  scenarios_generated: number;
  attack_scenarios: number;
  benign_scenarios: number;
  attack_ratio: number;
  last_scenario: string | null;
  last_event_at: string | null;
  last_attack_id: string | null;
  last_error: string | null;
}

export interface LiveItems<T> {
  items: T[];
  count: number;
}

export type LiveEventItems = LiveItems<CanonicalEvent>;
export type LiveIncidentItems = LiveItems<Investigation>;
