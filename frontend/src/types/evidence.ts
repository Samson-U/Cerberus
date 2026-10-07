import type { CanonicalEvent } from "./event";

export interface Evidence extends CanonicalEvent {
  investigation_id: string;
  stage: string;
  verification_status: "Verified" | "Unverified";
}
