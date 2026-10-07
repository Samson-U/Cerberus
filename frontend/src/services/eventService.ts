import type { CanonicalEvent } from "../types/event";
import { investigationService } from "./investigationService";

export const eventService = {
  getEvents: (investigationId: string, signal?: AbortSignal): Promise<CanonicalEvent[]> =>
    investigationService.getEvidence(investigationId, signal),
};
