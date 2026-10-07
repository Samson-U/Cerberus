import { createContext, useContext } from "react";
import type { DashboardData } from "../services/dashboardService";
import type { CanonicalEvent, TimelineEntry } from "../types/event";
import type { Entity } from "../types/entity";
import type { Graph } from "../types/graph";
import type { Investigation } from "../types/investigation";

export interface EvidenceItem {
  id: string;
  time: string;
  title: string;
  detail: string;
  source: string;
  type: string;
  stage: string;
  severity: string;
  icon: "login" | "usb" | "copy" | "search" | "file";
  raw: CanonicalEvent;
}

export interface CerberusData {
  dashboard: DashboardData | null;
  investigations: Investigation[];
  currentInvestigation: Investigation | null;
  timeline: TimelineEntry[];
  timelineItems: EvidenceItem[];
  evidence: EvidenceItem[];
  entities: Entity[];
  graph: Graph;
}

export const CerberusDataContext = createContext<CerberusData | null>(null);

export function useCerberusData(): CerberusData {
  const value = useContext(CerberusDataContext);
  if (!value) throw new Error("Cerberus data is unavailable outside its provider");
  return value;
}
