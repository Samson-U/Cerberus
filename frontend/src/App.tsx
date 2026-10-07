import { useEffect, useMemo, useState, type ElementType, type ReactNode } from "react";
import { CerberusDataContext, useCerberusData, type EvidenceItem } from "./data/CerberusDataContext";
import { aiService } from "./services/aiService";
import { dashboardService } from "./services/dashboardService";
import { investigationService } from "./services/investigationService";
import { reportService } from "./services/reportService";
import { threatService } from "./services/threatService";
import { settingsService } from "./services/settingsService";
import { simulationService } from "./services/simulationService";
import type { AIAnalysis } from "./types/ai";
import type { Report as ReportModel } from "./types/report";
import type { Investigation as InvestigationRecord } from "./types/investigation";
import type { CanonicalEvent, TimelineEntry } from "./types/event";
import type { Entity } from "./types/entity";
import type { Graph } from "./types/graph";
import type { SimulationScenario } from "./types/simulation";

type Page =
  | "Overview"
  | "Active Threats"
  | "Investigations"
  | "Reports"
  | "Settings";

type InvestigationTab = "Overview" | "Timeline" | "Attack Graph" | "Evidence" | "Entities" | "AI Analysis";
type ThreatSeverity = "Critical" | "High" | "Medium" | "Low";
type ThreatStatus = "Investigating" | "Contained" | "Completed" | "Resolved" | "False Positive";

type Threat = {
  id: string;
  title: string;
  severity: ThreatSeverity;
  status: ThreatStatus;
  user: string;
  device: string;
  firstDetected: string;
  lastActivity: string;
  confidence: number;
  evidenceCount: number;
  stage: string;
};

type IconName =
  | "grid"
  | "alert"
  | "case"
  | "graph"
  | "timeline"
  | "evidence"
  | "entities"
  | "report"
  | "search"
  | "bell"
  | "chevron"
  | "spark"
  | "shield"
  | "server"
  | "settings"
  | "database"
  | "close"
  | "filter"
  | "clock"
  | "link"
  | "check"
  | "external"
  | "zoomIn"
  | "zoomOut"
  | "target"
  | "file"
  | "usb"
  | "login"
  | "copy";

const iconPaths: Record<IconName, ReactNode> = {
  grid: <><rect x="3" y="3" width="7" height="7" rx="1" /><rect x="14" y="3" width="7" height="7" rx="1" /><rect x="3" y="14" width="7" height="7" rx="1" /><rect x="14" y="14" width="7" height="7" rx="1" /></>,
  alert: <><path d="M12 9v4" /><path d="M12 17h.01" /><path d="M10.3 3.7 2.8 17a2 2 0 0 0 1.7 3h15a2 2 0 0 0 1.7-3L13.7 3.7a2 2 0 0 0-3.4 0Z" /></>,
  case: <><rect x="3" y="7" width="18" height="13" rx="2" /><path d="M8 7V5a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2M3 12h18M10 12v2h4v-2" /></>,
  graph: <><circle cx="5" cy="6" r="2.5" /><circle cx="19" cy="6" r="2.5" /><circle cx="12" cy="18" r="2.5" /><path d="m7.2 7.2 3.5 8.4M16.8 7.2l-3.5 8.4M7.5 6h9" /></>,
  timeline: <><path d="M4 6h6M14 6h6M8 12h8M4 18h6M14 18h6" /><circle cx="12" cy="6" r="2" /><circle cx="6" cy="12" r="2" /><circle cx="12" cy="18" r="2" /></>,
  evidence: <><path d="M6 3h9l4 4v14H6z" /><path d="M14 3v5h5M9 13h6M9 17h6" /></>,
  entities: <><circle cx="9" cy="8" r="3" /><path d="M3.5 20a5.5 5.5 0 0 1 11 0M16 8h5M18.5 5.5v5" /></>,
  report: <><path d="M5 3h14v18H5z" /><path d="M9 17v-4M12 17V9M15 17v-6" /></>,
  search: <><circle cx="11" cy="11" r="7" /><path d="m20 20-4-4" /></>,
  bell: <><path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9M10 21h4" /></>,
  chevron: <path d="m9 18 6-6-6-6" />,
  spark: <><path d="m12 3 1.3 4.2L17 9l-3.7 1.8L12 15l-1.3-4.2L7 9l3.7-1.8zM19 15l.6 2 1.9 1-1.9.9-.6 2.1-.6-2.1-1.9-.9 1.9-1zM5 3l.6 2 1.9 1-1.9.9L5 9l-.6-2.1L2.5 6l1.9-1z" /></>,
  shield: <><path d="M12 3 4 6v5c0 5.2 3.4 8.8 8 10 4.6-1.2 8-4.8 8-10V6z" /><path d="m9 12 2 2 4-5" /></>,
  server: <><rect x="3" y="4" width="18" height="6" rx="2" /><rect x="3" y="14" width="18" height="6" rx="2" /><path d="M7 7h.01M7 17h.01" /></>,
  settings: <><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-2.8 2.8-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.6v.2h-4V21a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1L4.2 17l.1-.1a1.7 1.7 0 0 0 .3-1.9A1.7 1.7 0 0 0 3 14H2.8v-4H3a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9L4.2 7 7 4.2l.1.1A1.7 1.7 0 0 0 9 4.6a1.7 1.7 0 0 0 1-1.6v-.2h4V3a1.7 1.7 0 0 0 1 1.6 1.7 1.7 0 0 0 1.9-.3l.1-.1L19.8 7l-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.6 1h.2v4H21a1.7 1.7 0 0 0-1.6 1Z" /></>,
  database: <><ellipse cx="12" cy="5" rx="8" ry="3" /><path d="M4 5v6c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 11v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6" /></>,
  close: <><path d="m6 6 12 12M18 6 6 18" /></>,
  filter: <path d="M4 5h16l-6 7v6l-4 2v-8z" />,
  clock: <><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></>,
  link: <><path d="M10 13a5 5 0 0 0 7.5.5l2-2a5 5 0 0 0-7-7l-1.2 1.2M14 11a5 5 0 0 0-7.5-.5l-2 2a5 5 0 0 0 7 7l1.2-1.2" /></>,
  check: <path d="m5 12 4 4L19 6" />,
  external: <><path d="M14 4h6v6M20 4l-9 9" /><path d="M18 13v6H5V6h6" /></>,
  zoomIn: <><circle cx="10.5" cy="10.5" r="6.5" /><path d="m16 16 4 4M8 10.5h5M10.5 8v5" /></>,
  zoomOut: <><circle cx="10.5" cy="10.5" r="6.5" /><path d="m16 16 4 4M8 10.5h5" /></>,
  target: <><circle cx="12" cy="12" r="8" /><circle cx="12" cy="12" r="3" /><path d="M12 2v3M12 19v3M2 12h3M19 12h3" /></>,
  file: <><path d="M6 3h8l4 4v14H6z" /><path d="M14 3v5h4" /></>,
  usb: <><path d="M12 3v13M12 3l-2 2M12 3l2 2M12 10l4-2v-2M12 13l-4-2V9M9 21h6v-5H9z" /><circle cx="8" cy="8" r="1" /></>,
  login: <><path d="M10 5H5v14h5M13 8l4 4-4 4M17 12H8" /></>,
  copy: <><rect x="8" y="8" width="12" height="12" rx="2" /><path d="M16 8V4H4v12h4" /></>,
};

function Icon({ name, size = 18 }: { name: IconName; size?: number }) {
  return (
    <svg className="icon" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      {iconPaths[name]}
    </svg>
  );
}

function Button({ children, variant = "primary", icon, onClick, ariaLabel }: { children?: ReactNode; variant?: "primary" | "secondary" | "ghost" | "icon"; icon?: IconName; onClick?: () => void; ariaLabel?: string }) {
  return <button type="button" className={`button button--${variant}`} onClick={() => onClick?.()} aria-label={ariaLabel}>{icon && <Icon name={icon} size={16} />}{children}</button>;
}

function Badge({ children, tone = "neutral", dot = false }: { children: ReactNode; tone?: "critical" | "high" | "medium" | "low" | "neutral" | "blue"; dot?: boolean }) {
  return <span className={`badge badge--${tone}`}>{dot && <span className="badge__dot" />}{children}</span>;
}

function Heading({ level = 2, children, className = "", id }: { level?: 1 | 2 | 3 | 4; children: ReactNode; className?: string; id?: string }) {
  const Tag = `h${level}` as ElementType;
  return <Tag className={className} id={id}>{children}</Tag>;
}

const primaryNav: { label: Page; icon: IconName }[] = [
  { label: "Overview", icon: "grid" },
  { label: "Active Threats", icon: "alert" },
  { label: "Investigations", icon: "case" },
  { label: "Reports", icon: "report" },
];

type StageCard = { name: string; confidence: number; events: number; range: string; tone: string };

const eventIcon = (eventType: string): EvidenceItem["icon"] => {
  if (eventType.startsWith("LOGON")) return "login";
  if (eventType === "USB_INSERT" || eventType === "USB_REMOVE") return "usb";
  if (eventType.includes("COPY") || eventType.includes("WRITE")) return "copy";
  if (eventType.includes("HTTP") || eventType.includes("URL")) return "search";
  return "file";
};

const displayStage = (stage: string | undefined) =>
  stage ? stage.toLowerCase().replace(/(^|_)\w/g, (part) => part.toUpperCase()).replace(/_/g, " ") : "Investigation";

const toEvidenceItems = (
  events: (CanonicalEvent | TimelineEntry)[],
  timeline: TimelineEntry[],
): EvidenceItem[] => {
  const stages = new Map(timeline.map((item) => [item.event_id, item.stage]));
  return events.map((event) => ({
    id: event.event_id,
    time: event.timestamp.slice(11, 19),
    title: ("event" in event && event.event) ? event.event : event.event_type,
    detail: event.description ?? (("event" in event && event.event) ? event.event : undefined) ?? event.event_type.replace(/_/g, " ").toLowerCase(),
    source: event.source_log,
    type: event.event_category,
    stage: displayStage(stages.get(event.event_id)),
    severity: event.severity.toLowerCase(),
    icon: eventIcon(event.event_type),
    raw: event,
  }));
};

const toneFor = (confidence: number) =>
  confidence >= 0.9 ? "critical" : confidence >= 0.75 ? "high" : "medium";

const toStageCards = (incident: InvestigationRecord | null): StageCard[] =>
  (incident?.stage_records ?? []).map((stage) => ({
    name: displayStage(stage.stage),
    confidence: Math.round(stage.confidence * 100),
    events: stage.evidence.length,
    range: `${stage.start_time.slice(11, 16)}–${stage.end_time.slice(11, 16)}`,
    tone: toneFor(stage.confidence),
  }));

function Sidebar({ page, setPage, activeThreatCount }: { page: Page; setPage: (page: Page) => void; activeThreatCount: number }) {
  const { dashboard } = useCerberusData();
  return (
    <aside className="sidebar">
      <div className="brand"><div className="brand__mark"><Icon name="shield" size={20} /></div><div><strong>CERBERUS</strong><span>Threat Intelligence</span></div></div>
      <nav className="nav" aria-label="Primary navigation">
        <span className="nav__label">Workspace</span>
        {primaryNav.map((item) => (
          <button key={item.label} className={`nav__item ${page === item.label ? "is-active" : ""}`} onClick={() => setPage(item.label)}>
            <Icon name={item.icon} size={17} /><span>{item.label}</span>{item.label === "Active Threats" && <span className="nav__count">{activeThreatCount}</span>}
          </button>
        ))}
      </nav>
      <div className="sidebar__footer">
        <div className="system-card">
          <div className="system-card__top"><span><span className={`status-dot status-dot--${dashboard ? "green" : "blue"}`} />{dashboard ? "API connected" : "Connecting to API"}</span></div>
          <div className="system-card__bar"><span /></div>
        </div>
        <button className="nav__item" onClick={() => setPage("Settings")}><Icon name="database" size={17} /><span>Data sources</span></button>
        <button className={`nav__item ${page === "Settings" ? "is-active" : ""}`} onClick={() => setPage("Settings")}><Icon name="settings" size={17} /><span>Settings</span></button>
        <div className="analyst analyst--side"><div className="avatar">A</div><div><strong>Analyst</strong><span>Security Operations</span></div><Icon name="chevron" size={15} /></div>
      </div>
    </aside>
  );
}

function Topbar({ page }: { page: Page }) {
  const { dashboard } = useCerberusData();
  return (
    <header className="topbar">
      <div className="breadcrumbs"><span>Security Operations</span><Icon name="chevron" size={13} /><strong>{page}</strong></div>
      <div className="topbar__right">
        <label className="searchbox"><Icon name="search" size={17} /><input placeholder="Search incidents, entities, events…" aria-label="Global search" /><kbd>⌘ K</kbd></label>
        <div className="environment"><span className={`status-dot status-dot--${dashboard ? "green" : "blue"}`} /><span>{dashboard ? "Connected" : "Connecting"}</span><Icon name="chevron" size={13} /></div>
        <button className="icon-button" aria-label="Notifications"><Icon name="bell" size={18} /><span className="notification-dot" /></button>
        <div className="avatar avatar--small">A</div>
      </div>
    </header>
  );
}

function KpiCard({ label, value, note, icon, tone, chart, onClick }: { label: string; value: string; note: string; icon: IconName; tone: string; chart: number[]; onClick?: () => void }) {
  return (
    <article className={`kpi-card ${onClick ? "kpi-card--clickable" : ""}`} onClick={onClick}>
      <div className={`kpi-card__icon tone-${tone}`}><Icon name={icon} size={17} /></div>
      <div className="kpi-card__label">{label}</div>
      <div className="kpi-card__body"><strong>{value}</strong><svg className={`sparkline tone-${tone}`} viewBox="0 0 90 30" preserveAspectRatio="none"><polyline points={chart.map((v, i) => `${i * 15},${30 - v}`).join(" ")} fill="none" stroke="currentColor" strokeWidth="2" /></svg></div>
      <div className="kpi-card__note">{note}</div>
    </article>
  );
}

function ActivityChart({ series }: { series: { timestamp: string; count: number }[] }) {
  const values = series.map((point) => point.count);
  const maximum = Math.max(...values, 1);
  const points = values.map((value, index) => {
    const x = values.length < 2 ? 400 : (index / (values.length - 1)) * 800;
    const y = 125 - (value / maximum) * 110;
    return `${x},${y}`;
  });
  const polyline = points.join(" ");
  const area = points.length > 1
    ? `M${points[0]} L${points.slice(1).join(" L")} L800 135 L0 135 Z`
    : points.length === 1
      ? `M${points[0]} L800 135 L0 135 Z`
      : "";
  return (
    <div className="activity-chart">
      <div className="activity-chart__axis"><span>{maximum}</span><span>{Math.round(maximum * 0.66)}</span><span>{Math.round(maximum * 0.33)}</span><span>0</span></div>
      <div className="activity-chart__plot">
        <div className="chart-grid" />
        <svg viewBox="0 0 800 135" preserveAspectRatio="none" aria-label="Evidence activity across reconstructed attacks">
          <defs><linearGradient id="area" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="var(--danger)" stopOpacity=".2" /><stop offset="1" stopColor="var(--danger)" stopOpacity="0" /></linearGradient></defs>
          {area && <path d={area} fill="url(#area)" />}
          {polyline && <polyline points={polyline} fill="none" stroke="var(--danger)" strokeWidth="2" />}
        </svg>
        <div className="chart-tooltip"><strong>{series.at(-1)?.timestamp ?? "No activity"}</strong><span>Evidence events</span><em>{series.at(-1)?.count ?? 0} events</em></div>
        <div className="activity-chart__labels">{series.map((point) => <span key={point.timestamp}>{point.timestamp.slice(5)}</span>)}</div>
      </div>
    </div>
  );
}

function ThreatCard({ threat, onInvestigate }: { threat: Threat; onInvestigate: (incidentId: string) => void }) {
  return (
    <article className="threat-card">
      <div className="threat-card__severity"><Icon name="alert" size={19} /></div>
      <div className="threat-card__main">
        <div className="threat-card__heading"><div><Badge tone={threat.severity.toLowerCase() as "critical" | "high" | "medium"} dot>{threat.severity} risk</Badge><Heading level={3}>{threat.title}</Heading><p>Reconstructed from CERT event evidence</p></div><div className="threat-card__score"><strong>{threat.confidence}%</strong><span>confidence</span></div></div>
        <div className="threat-card__meta">
          <div><span>User</span><strong><span className="mini-avatar">{threat.user.split(" ").map((part) => part[0]).join("").slice(0, 2)}</span>{threat.user}</strong></div>
          <div><span>Device</span><strong><Icon name="server" size={15} />{threat.device}</strong></div>
          <div><span>First detected</span><strong>{threat.firstDetected}</strong></div>
          <div><span>Evidence</span><strong>{threat.evidenceCount} events</strong></div>
        </div>
      </div>
      <Button variant="secondary" onClick={() => onInvestigate(threat.id)}>Investigate <Icon name="chevron" size={14} /></Button>
    </article>
  );
}

function EventsTable({ compact = false, events }: { compact?: boolean; events: CanonicalEvent[] }) {
  const rows = [...events].sort((a, b) => b.timestamp.localeCompare(a.timestamp));
  return (
    <div className="table-wrap">
      <table>
        <thead><tr><th>Timestamp</th><th>Event</th><th>User</th><th>Device</th><th>Source</th><th>Severity</th><th>Status</th><th /></tr></thead>
        <tbody>{rows.slice(0, compact ? 4 : 5).map((event) => (
          <tr key={event.event_id}>
            <td className="mono">{event.timestamp.slice(11, 19)}</td><td><strong>{event.description ?? event.event_type}</strong></td><td>{event.user_id ?? "—"}</td><td className="mono">{event.device_id ?? "—"}</td><td>{event.source_log}</td>
            <td><Badge tone={event.severity.toLowerCase() as "critical" | "high" | "medium"}>{event.severity}</Badge></td><td><span className="table-status"><span className="status-dot status-dot--blue" />Observed</span></td><td><Icon name="chevron" size={14} /></td>
          </tr>
        ))}</tbody>
      </table>
    </div>
  );
}

function Overview({ threats, onInvestigate, onActiveThreats, simulationRunning, onToggleSimulation, onResetSimulation }: { threats: Threat[]; onInvestigate: (incidentId: string) => void; onActiveThreats: () => void; simulationRunning: boolean; onToggleSimulation: () => void; onResetSimulation: () => void }) {
  const { dashboard } = useCerberusData();
  const sparkline = dashboard?.activity_series.map((point) => point.count) ?? [];
  const critical = threats.filter((threat) => threat.severity === "Critical").length;
  const high = threats.filter((threat) => threat.severity === "High").length;
  const medium = threats.filter((threat) => threat.severity === "Medium").length;
  return (
    <div className="page">
      <div className="page-heading"><div><div className="eyebrow">{dashboard?.generated_at ? new Date(dashboard.generated_at).toLocaleString() : "Security Operations"}</div><Heading level={1}>Security Overview</Heading><p>Real-time posture and reconstructed attack activity across your environment.</p><div className="section-heading"><Button onClick={onToggleSimulation}>{simulationRunning ? "Stop Simulation" : "Start Simulation"}</Button><Button variant="secondary" onClick={onResetSimulation}>Reset Demo</Button></div></div><div className="posture"><div className="posture__ring"><strong>{dashboard?.security_posture ?? "—"}</strong></div><div><span>Security posture</span><strong>{(dashboard?.security_posture ?? 0) < 60 ? "Elevated risk" : "Monitored"}</strong><small>Derived from reconstructed incidents</small></div></div></div>
      <div className="kpi-grid">
        <KpiCard label="Active Threats" value={String(threats.length)} note={`${critical} critical · ${high} high · ${medium} medium`} icon="alert" tone="danger" chart={sparkline} onClick={onActiveThreats} />
        <KpiCard label="Critical Incidents" value={String(dashboard?.critical_incidents ?? 0)} note="Requires immediate action" icon="shield" tone="danger" chart={sparkline} />
        <KpiCard label="Events Processed" value={String(dashboard?.events_processed ?? "—")} note="Simulated runtime events" icon="database" tone="blue" chart={sparkline} />
        <KpiCard label="Suspicious Entities" value={String(dashboard?.suspicious_entities ?? "—")} note="Entities in reconstructed attacks" icon="entities" tone="warning" chart={sparkline} />
        <KpiCard label="Attacks Reconstructed" value={String(dashboard?.reconstructed_attacks ?? "—")} note="From generated attack chains" icon="graph" tone="blue" chart={sparkline} />
      </div>
      <section className="section">
        <div className="section-heading"><div><Heading level={2}>Active Threats</Heading><span className="section-count">{threats.length} open</span></div><Button variant="ghost" onClick={onActiveThreats}>View all threats <Icon name="chevron" size={14} /></Button></div>
        {threats[0] && <ThreatCard threat={threats[0]} onInvestigate={onInvestigate} />}
        <div className="minor-threats">
          {threats.slice(1, 3).map((threat) => <div key={threat.id}><Badge tone={threat.severity.toLowerCase() as "critical" | "high" | "medium"}>{threat.severity}</Badge><strong>{threat.title}</strong><span>{threat.user}</span><span>{threat.device}</span><span>{threat.confidence}% confidence</span></div>)}
        </div>
      </section>
      <section className="section panel">
        <div className="section-heading section-heading--panel"><div><Heading level={2}>Attack Activity</Heading><span className="muted">Evidence events by date from reconstructed attacks</span></div><div className="legend"><span><i className="legend-danger" />Evidence events</span><Button variant="ghost" icon="filter">Filter</Button></div></div>
        <ActivityChart series={dashboard?.activity_series ?? []} />
      </section>
      <section className="section panel">
        <div className="section-heading section-heading--panel"><div><Heading level={2}>Recent Security Events</Heading><span className="muted">Events prioritized by correlation significance</span></div><Button variant="ghost">View event stream <Icon name="external" size={14} /></Button></div>
        <EventsTable compact events={dashboard?.recent_events ?? []} />
      </section>
    </div>
  );
}

function ActiveThreats({ threats, onInvestigate, onStatusChange }: { threats: Threat[]; onInvestigate: (incidentId: string) => void; onStatusChange: (incidentId: string, status: ThreatStatus) => Promise<void> }) {
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("All");
  const [status, setStatus] = useState("All");
  const [sort, setSort] = useState("Highest risk");
  const [openMenu, setOpenMenu] = useState<string | null>(null);
  const [pending, setPending] = useState<{ threat: Threat; status: ThreatStatus } | null>(null);
  const [toast, setToast] = useState("");
  const rank: Record<ThreatSeverity, number> = { Critical: 4, High: 3, Medium: 2, Low: 1 };

  const filtered = [...threats]
    .filter((threat) => `${threat.id} ${threat.title} ${threat.user} ${threat.device}`.toLowerCase().includes(search.toLowerCase()))
    .filter((threat) => severity === "All" || threat.severity === severity)
    .filter((threat) => status === "All" || threat.status === status)
    .sort((a, b) => {
      if (sort === "Highest confidence") return b.confidence - a.confidence;
      if (sort === "Oldest unresolved") return a.id.localeCompare(b.id);
      if (sort === "Most recent") return b.lastActivity.localeCompare(a.lastActivity);
      return rank[b.severity] - rank[a.severity] || b.confidence - a.confidence;
    });

  const confirmStatus = async () => {
    if (!pending) return;
    const item = pending;
    setPending(null);
    try {
      await onStatusChange(item.threat.id, item.status);
      setToast(`Incident ${item.threat.id} marked as ${item.status.toLowerCase()}`);
      setTimeout(() => setToast(""), 3000);
    } catch {
      setToast("");
    }
  };

  const count = (level: ThreatSeverity) => threats.filter((threat) => threat.severity === level).length;

  return (
    <div className="page">
      <div className="page-heading"><div><div className="eyebrow">Security Operations</div><Heading level={1}>Active Threats</Heading><p>Live unresolved threats prioritized by reconstructed impact and confidence.</p></div></div>
      <div className="threat-summary">
        <div><span className="summary-severity summary-severity--critical" /><strong>{count("Critical")}</strong><span>Critical</span></div>
        <div><span className="summary-severity summary-severity--high" /><strong>{count("High")}</strong><span>High</span></div>
        <div><span className="summary-severity summary-severity--medium" /><strong>{count("Medium")}</strong><span>Medium</span></div>
        <div className="threat-summary__total"><Icon name="alert" size={17} /><strong>{threats.length}</strong><span>Total Active</span></div>
      </div>
      <div className="filterbar active-threat-filters">
        <label><Icon name="search" size={16} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search incidents..." /></label>
        <select value={severity} onChange={(event) => setSeverity(event.target.value)} aria-label="Severity filter"><option>All</option><option>Critical</option><option>High</option><option>Medium</option></select>
        <select value={status} onChange={(event) => setStatus(event.target.value)} aria-label="Status filter"><option>All</option><option>Investigating</option><option>Contained</option></select>
        {["Attack Type", "User", "Device", "Time", "Confidence"].map((filter) => <button key={filter}>{filter}<Icon name="chevron" size={12} /></button>)}
        <select className="sort-select" value={sort} onChange={(event) => setSort(event.target.value)} aria-label="Sort threats"><option>Highest risk</option><option>Most recent</option><option>Oldest unresolved</option><option>Highest confidence</option></select>
      </div>
      <div className="panel active-threat-table">
        <table>
          <thead><tr><th>Incident</th><th>Severity / Status</th><th>User / Device</th><th>First / Last Activity</th><th>Confidence</th><th>Evidence</th><th>Current Stage</th><th>Action</th><th /></tr></thead>
          <tbody>{filtered.map((threat) => (
            <tr key={threat.id} onClick={() => onInvestigate(threat.id)}>
              <td><strong className="mono table-link">{threat.id}</strong><span className="cell-secondary">{threat.title}</span></td>
              <td><Badge tone={threat.severity.toLowerCase() as "critical" | "high" | "medium"}>{threat.severity}</Badge><span className="cell-secondary status-line"><span className={`status-dot status-dot--${threat.status === "Contained" ? "green" : "blue"}`} />{threat.status}</span></td>
              <td><strong>{threat.user}</strong><span className="cell-secondary mono">{threat.device}</span></td>
              <td><strong>{threat.firstDetected}</strong><span className="cell-secondary">Last: {threat.lastActivity}</span></td>
              <td><strong>{threat.confidence}%</strong></td><td>{threat.evidenceCount} events</td><td><strong>{threat.stage}</strong></td>
              <td><Button variant="secondary" onClick={() => onInvestigate(threat.id)}>View Investigation</Button></td>
              <td className="overflow-cell" onClick={(event) => event.stopPropagation()}>
                <button className="overflow-button" onClick={() => setOpenMenu(openMenu === threat.id ? null : threat.id)} aria-label={`Actions for ${threat.id}`}>•••</button>
                {openMenu === threat.id && <div className="status-menu">{(["Investigating", "Contained", "Resolved", "False Positive"] as ThreatStatus[]).map((nextStatus) => <button key={nextStatus} disabled={nextStatus === threat.status} onClick={() => { setPending({ threat, status: nextStatus }); setOpenMenu(null); }}>Mark as {nextStatus}</button>)}</div>}
              </td>
            </tr>
          ))}</tbody>
        </table>
        {!filtered.length && <div className="queue-empty"><Icon name="check" size={22} /><Heading level={3}>No threats match these filters</Heading><p>Resolved and false-positive incidents remain available in Investigations.</p></div>}
      </div>
      <div className="queue-logic"><span><b>Detected</b><Icon name="chevron" size={12} /><b>Investigating</b><Icon name="chevron" size={12} /><b>Contained</b><em>Remains visible until explicitly resolved or closed</em></span></div>
      {pending && <div className="confirmation-backdrop"><div className="confirmation-dialog" role="dialog" aria-modal="true"><div className="confirmation-dialog__icon"><Icon name={pending.status === "Resolved" ? "check" : "alert"} size={20} /></div><Heading level={2}>Mark Incident as {pending.status}?</Heading><strong className="mono">{pending.threat.id}</strong><p>{pending.threat.title}</p><div className="confirmation-copy">Are you sure this incident has been investigated and the required remediation has been completed?</div><div className="confirmation-actions"><Button variant="ghost" onClick={() => setPending(null)}>Cancel</Button><Button onClick={confirmStatus}>Mark as {pending.status}</Button></div></div></div>}
      {toast && <div className="toast"><Icon name="check" size={15} />{toast}</div>}
    </div>
  );
}

function ThreatAlert({ threat, onView, onDismiss }: { threat: Threat; onView: () => void; onDismiss: () => void }) {
  return (
    <div className="alert-overlay">
      <div className="threat-alert" role="alertdialog" aria-labelledby="threat-title">
        <div className="threat-alert__rail" />
        <div className="threat-alert__header">
          <div className="alert-icon"><Icon name="alert" size={21} /><span /></div>
          <div><div className="alert-kicker"><span className="pulse-dot" />Active threat detected</div><Heading level={2} id="threat-title">{threat.title}</Heading></div>
          <button className="icon-button" onClick={onDismiss} aria-label="Dismiss alert"><Icon name="close" size={18} /></button>
        </div>
        <p>CERBERUS reconstructed an attack chain from {threat.evidenceCount} evidence events.</p>
        <div className="threat-alert__details">
          <div><span>Risk</span><Badge tone={threat.severity.toLowerCase() as "critical" | "high" | "medium"} dot>{threat.severity}</Badge></div>
          <div><span>User</span><strong>{threat.user}</strong></div>
          <div><span>Device</span><strong className="mono">{threat.device}</strong></div>
          <div><span>Confidence</span><strong>{threat.confidence}%</strong></div>
        </div>
        <div className="threat-alert__context"><Icon name="clock" size={16} /><span>First detected {threat.firstDetected}</span></div>
        <div className="threat-alert__actions"><Button variant="ghost" onClick={onDismiss}>Dismiss</Button><Button onClick={onView}>View Investigation <Icon name="chevron" size={14} /></Button></div>
      </div>
    </div>
  );
}

function IncidentHeader({ incidentId, status, onBack, onOverview, onGraph, onAI, onGenerateReport }: { incidentId: string; status: ThreatStatus; onBack: () => void; onOverview: () => void; onGraph: () => void; onAI: () => void; onGenerateReport: () => void }) {
  const { investigations } = useCerberusData();
  const incident = investigationRows(investigations).find((row) => row[0] === incidentId) ?? investigationRows(investigations)[0];
  if (!incident) return null;
  const [id, attackType, severity, user, device, startTime, duration, confidence] = incident;
  const title = attackType;
  const initials = user.split(" ").map((part) => part[0]).join("").slice(0, 2);
  return (
    <>
      <div className="incident-top">
        <div><div className="eyebrow"><button className="back-link" onClick={onBack}>Investigations</button><Icon name="chevron" size={12} /><button className="back-link" onClick={onOverview}>{id}</button></div><div className="incident-title"><Heading level={1}>{title}</Heading><Badge tone={severity.toLowerCase() as "critical" | "high" | "medium"} dot>{severity} risk</Badge></div><p>Incident <span className="mono">#{id}</span> · Reconstructed from CERT logon, device, and file events</p></div>
        <div className="incident-actions"><Button variant="secondary" icon="graph" onClick={onGraph}>Open attack graph</Button><Button icon="spark" onClick={onAI}>AI incident analysis</Button>{status !== "Resolved" && status !== "Completed" && <Button variant="secondary" icon="report" onClick={onGenerateReport}>Generate report</Button>}</div>
      </div>
      <div className="incident-facts">
        <div><span>Primary user</span><strong><span className="mini-avatar">{initials}</span>{user}</strong></div>
        <div><span>Primary device</span><strong><Icon name="server" size={15} />{device}</strong></div>
        <div><span>Detection time</span><strong>{startTime}</strong></div>
        <div><span>Duration</span><strong>{duration}</strong></div>
        <div><span>Confidence</span><strong className="confidence">{confidence}</strong></div>
        <div><span>Status</span><strong><span className={`status-dot status-dot--${status === "Resolved" ? "green" : "blue"}`} />{status}</strong></div>
        <div><span>Correlated</span><strong>{investigations.find((row) => row.id === id)?.evidence_count ?? 0} events</strong></div>
      </div>
    </>
  );
}

function InvestigationTabs({ active, onChange }: { active: InvestigationTab; onChange: (tab: InvestigationTab) => void }) {
  const tabs: { label: InvestigationTab; icon: IconName }[] = [
    { label: "Overview", icon: "grid" },
    { label: "Timeline", icon: "timeline" },
    { label: "Attack Graph", icon: "graph" },
    { label: "Evidence", icon: "evidence" },
    { label: "Entities", icon: "entities" },
    { label: "AI Analysis", icon: "spark" },
  ];

  return (
    <nav className="investigation-tabs" aria-label="Investigation views">
      {tabs.map((tab) => (
        <button key={tab.label} className={active === tab.label ? "is-active" : ""} onClick={() => onChange(tab.label)}>
          <Icon name={tab.icon} size={15} />
          <span>{tab.label}</span>
        </button>
      ))}
    </nav>
  );
}

function AttackStages({ selected, onSelect, items }: { selected: string; onSelect: (stage: string) => void; items: StageCard[] }) {
  return (
    <div className="stage-track">
      {items.map((stage, index) => (
        <div className="stage-track__item" key={stage.name}>
          <button className={`stage-card ${selected === stage.name ? "is-selected" : ""}`} onClick={() => onSelect(stage.name)}>
            <div className="stage-card__top"><span className={`stage-index tone-${stage.tone}`}>{index + 1}</span><span>{stage.confidence}%</span></div>
            <strong>{stage.name}</strong><small>{stage.range}</small>
            <div className="stage-card__foot"><span>{stage.events} {stage.events === 1 ? "event" : "events"}</span><span className="confidence-bar"><i style={{ width: `${stage.confidence}%` }} /></span></div>
          </button>
          {index < items.length - 1 && <div className="stage-connector"><span /><Icon name="chevron" size={14} /></div>}
        </div>
      ))}
    </div>
  );
}

function EvidenceDetail({ item }: { item: EvidenceItem }) {
  const [rawOpen, setRawOpen] = useState(false);
  return (
    <div className="evidence-detail">
      <div className="evidence-detail__head"><div className={`event-icon tone-${item.severity}`}><Icon name={item.icon} size={18} /></div><div><div><Badge tone={item.severity as "critical" | "high" | "medium"}>{item.stage}</Badge><span className="mono">{item.id}</span></div><Heading level={3}>{item.title}</Heading><p>{item.detail}</p></div></div>
      <div className="detail-grid">
        <div><span>Timestamp</span><strong>{item.raw.timestamp}</strong></div><div><span>Source log</span><strong>{item.source}</strong></div>
        <div><span>Event type</span><strong>{item.type}</strong></div><div><span>Correlation</span><strong>{item.stage}</strong></div>
        <div><span>User</span><strong>{item.raw.user_id ?? "Not recorded"}</strong></div><div><span>Device</span><strong>{item.raw.device_id ?? "Not recorded"}</strong></div>
      </div>
      <div className="metadata"><span>Relevant metadata</span><div>{Object.entries(item.raw.metadata).map(([key, value]) => <code key={key}>{key}: {String(value)}</code>)}</div></div>
      <button className="raw-toggle" onClick={() => setRawOpen(!rawOpen)}><span><Icon name="evidence" size={15} />View raw event</span><Icon name="chevron" size={14} /></button>
      {rawOpen && <pre className="raw-event">{JSON.stringify(item.raw, null, 2)}</pre>}
      <div className="trace-note"><Icon name="link" size={15} /><span>Supports <strong>{item.stage}</strong> stage in attack timeline</span></div>
    </div>
  );
}

function InvestigationTimeline({ items }: { items: EvidenceItem[] }) {
  const [selectedEvidence, setSelectedEvidence] = useState(items[0]);
  useEffect(() => setSelectedEvidence(items[0]), [items]);
  if (!items.length) return <div className="panel queue-empty">No evidence events are available for this investigation.</div>;
  return (
    <div className="investigation-tab-grid">
      <section className="panel attack-timeline-panel">
        <div className="panel-title"><div><Heading level={2}>Attack Timeline</Heading><span>{items.length} correlated events</span></div><Button variant="icon" icon="filter" ariaLabel="Filter timeline" /></div>
        <div className="timeline-list">
          {items.map((item) => (
            <button key={item.id} className={`timeline-event ${selectedEvidence.id === item.id ? "is-selected" : ""}`} onClick={() => setSelectedEvidence(item)}>
              <span className="timeline-event__time">{item.time.slice(0, 5)}<small>{item.time.slice(6)}</small></span>
              <span className={`timeline-event__marker tone-${item.severity}`}><Icon name={item.icon} size={15} /></span>
              <span className="timeline-event__body"><span><Badge tone={item.severity as "critical" | "high" | "medium" | "low"}>{item.stage === "Investigation" ? "Observed" : item.stage}</Badge><code>{item.id}</code></span><strong>{item.title}</strong><small>{item.detail}</small></span>
              <Icon name="chevron" size={15} />
            </button>
          ))}
        </div>
      </section>
      <section className="panel evidence-panel">
        <div className="panel-title"><div><Heading level={2}>Evidence Inspector</Heading><span>Normalized event record</span></div><Badge tone="blue">CERT source record</Badge></div>
        {selectedEvidence && <EvidenceDetail item={selectedEvidence} />}
      </section>
    </div>
  );
}

function InvestigationEvidence({ items, stageCards }: { items: EvidenceItem[]; stageCards: StageCard[] }) {
  const [selectedStage, setSelectedStage] = useState(stageCards[0]?.name ?? "Collection");
  const filtered = items.filter((item) => item.stage === selectedStage);
  const [selectedEvidence, setSelectedEvidence] = useState(items[0]);
  useEffect(() => setSelectedEvidence(items[0]), [items]);
  useEffect(() => setSelectedStage(stageCards[0]?.name ?? "Collection"), [stageCards]);
  if (!items.length) return <div className="panel queue-empty">No evidence events are available for this investigation.</div>;
  return (
    <>
      <section className="section">
        <div className="section-heading"><div><Heading level={2}>Evidence by Attack Stage</Heading><span className="muted">Records associated with the selected investigation</span></div><Badge tone="blue">Normalized CERT events</Badge></div>
        <AttackStages items={stageCards} selected={selectedStage} onSelect={(stage) => {
          setSelectedStage(stage);
          const first = items.find((item) => item.stage === stage);
          if (first) setSelectedEvidence(first);
        }} />
      </section>
      <div className="investigation-tab-grid">
        <section className="panel attack-timeline-panel">
          <div className="panel-title"><div><Heading level={2}>Supporting Evidence</Heading><span>{filtered.length} records for {selectedStage}</span></div></div>
          <div className="timeline-list">
            {filtered.map((item) => (
              <button key={item.id} className={`timeline-event ${selectedEvidence.id === item.id ? "is-selected" : ""}`} onClick={() => setSelectedEvidence(item)}>
                <span className="timeline-event__time">{item.time.slice(0, 5)}<small>{item.time.slice(6)}</small></span>
                <span className={`timeline-event__marker tone-${item.severity}`}><Icon name={item.icon} size={15} /></span>
                <span className="timeline-event__body"><span><Badge tone={item.severity as "critical" | "high" | "medium" | "low"}>{item.stage}</Badge><code>{item.id}</code></span><strong>{item.title}</strong><small>{item.source}</small></span>
                <Icon name="chevron" size={15} />
              </button>
            ))}
          </div>
        </section>
        <section className="panel evidence-panel">
          <div className="panel-title"><div><Heading level={2}>Evidence Inspector</Heading><span>Normalized event record</span></div><Badge tone="blue">CERT source record</Badge></div>
          {selectedEvidence && <EvidenceDetail item={selectedEvidence} />}
        </section>
      </div>
    </>
  );
}

function InvestigationEntities({ incidentId }: { incidentId: string }) {
  const { entities } = useCerberusData();
  const incidentEntities = entities.map((entity) => [
    entity.name,
    entity.entity_type,
    entity.context,
    `${entity.related_event_ids.length} events`,
    entity.risk,
  ]);
  const [selectedEntity, setSelectedEntity] = useState<string | null>(null);
  const entity = incidentEntities.find((item) => item[0] === selectedEntity);
  return (
    <section className="panel entities-panel">
      <div className="panel-title"><div><Heading level={2}>Investigation Entities</Heading><span>{incidentEntities.length} entities involved in {incidentId}</span></div><Button variant="secondary" icon="graph">View relationships</Button></div>
      <table>
        <thead><tr><th>Entity</th><th>Type</th><th>Context</th><th>Related activity</th><th>Risk</th><th /></tr></thead>
        <tbody>{incidentEntities.map((entity) => (
          <tr key={entity[0]} onClick={() => setSelectedEntity(entity[0])}>
            <td><strong>{entity[0]}</strong></td><td>{entity[1]}</td><td>{entity[2]}</td><td>{entity[3]}</td>
            <td><Badge tone={entity[4].toLowerCase() as "critical" | "high" | "medium"}>{entity[4]}</Badge></td><td><Icon name="chevron" size={14} /></td>
          </tr>
        ))}</tbody>
      </table>
      {entity && <div className="entity-detail entity-detail--inline">
        <div className="entity-detail__head"><Badge tone={entity[4].toLowerCase() as "critical" | "high" | "medium"} dot>{entity[4]} risk</Badge><Button variant="icon" icon="close" ariaLabel="Close entity details" onClick={() => setSelectedEntity(null)} /></div>
        <div className="entity-hero"><div className="entity-hero__icon"><Icon name={entity[1] === "User" ? "entities" : entity[1] === "Device" ? "server" : entity[1] === "USB device" ? "usb" : "file"} size={24} /></div><span>{entity[1]}</span><Heading level={2}>{entity[0]}</Heading></div>
        <div className="entity-section"><Heading level={3}>Entity details</Heading><dl><div><dt>Context</dt><dd>{entity[2]}</dd></div><div><dt>Related activity</dt><dd>{entity[3]}</dd></div><div><dt>Investigation</dt><dd className="mono">{incidentId}</dd></div></dl></div>
        <div className="entity-section"><div className="section-row"><Heading level={3}>Relationships</Heading><span>Related entities</span></div><div className="related-entity"><span className="related-icon"><Icon name="link" size={14} /></span><strong>{incidentId} attack path</strong></div></div>
      </div>}
    </section>
  );
}

function Investigation({ incidentId, status, activeTab, onTabChange, onBack, onGenerateReport }: { incidentId: string; status: ThreatStatus; activeTab: InvestigationTab; onTabChange: (tab: InvestigationTab) => void; onBack: () => void; onGenerateReport: () => void }) {
  const { evidence: incidentEvidence, timelineItems, timeline, currentInvestigation } = useCerberusData();
  const stageCards = useMemo(() => toStageCards(currentInvestigation), [currentInvestigation]);
  const [selectedStage, setSelectedStage] = useState(stageCards[0]?.name ?? "Collection");
  const filtered = useMemo(() => incidentEvidence.filter((item) => item.stage === selectedStage), [incidentEvidence, selectedStage]);
  const [selectedEvidence, setSelectedEvidence] = useState(incidentEvidence[0]);
  useEffect(() => setSelectedEvidence(incidentEvidence[0]), [incidentEvidence]);

  const selectStage = (stage: string) => {
    setSelectedStage(stage);
    const first = incidentEvidence.find((item) => item.stage === stage);
    if (first) setSelectedEvidence(first);
  };

  return (
    <div className="page page--incident">
      <IncidentHeader incidentId={incidentId} status={status} onBack={onBack} onOverview={() => onTabChange("Overview")} onGraph={() => onTabChange("Attack Graph")} onAI={() => onTabChange("AI Analysis")} onGenerateReport={onGenerateReport} />
      <InvestigationTabs active={activeTab} onChange={onTabChange} />
      {activeTab === "Overview" && <>
      <section className="section">
        <div className="section-heading"><div><Heading level={2}>Reconstructed Attack Chain</Heading><span className="muted">Select a stage to filter timeline and evidence</span></div><Badge tone="blue"><Icon name="spark" size={13} /> AI reconstructed</Badge></div>
        <AttackStages items={stageCards} selected={selectedStage} onSelect={selectStage} />
      </section>
      <div className="investigation-grid">
        <section className="panel attack-timeline-panel">
          <div className="panel-title"><div><Heading level={2}>Attack Timeline</Heading><span>{filtered.length} events in {selectedStage}</span></div><Button variant="icon" icon="filter" ariaLabel="Filter timeline" /></div>
          <div className="timeline-list">
            {filtered.map((item) => (
              <button key={item.id} className={`timeline-event ${selectedEvidence.id === item.id ? "is-selected" : ""}`} onClick={() => setSelectedEvidence(item)}>
                <span className="timeline-event__time">{item.time.slice(0, 5)}<small>{item.time.slice(6)}</small></span>
                <span className={`timeline-event__marker tone-${item.severity}`}><Icon name={item.icon} size={15} /></span>
                <span className="timeline-event__body"><span><Badge tone={item.severity as "critical" | "high" | "medium" | "low"}>{item.stage === "Investigation" ? "Observed" : item.stage}</Badge><code>{item.id}</code></span><strong>{item.title}</strong><small>{item.detail}</small></span>
                <Icon name="chevron" size={15} />
              </button>
            ))}
          </div>
          {timeline.filter((item) => !item.stage).length > 0 && <div className="timeline-context"><span className="normal-marker" /><div><span>{timeline.filter((item) => !item.stage).length} events</span><strong>Events outside detected stages</strong><small>Review the full incident timeline for additional context.</small></div><button onClick={() => onTabChange("Timeline")}>Review</button></div>}
        </section>
        <section className="panel evidence-panel">
          <div className="panel-title"><div><Heading level={2}>Evidence Inspector</Heading><span>Verified event record</span></div><Badge tone="low"><Icon name="check" size={12} /> Integrity verified</Badge></div>
          {selectedEvidence && <EvidenceDetail item={selectedEvidence} />}
        </section>
        <aside className="summary-column">
          <section className="panel summary-card">
            <div className="summary-card__title"><Icon name="spark" size={17} /><div><Heading level={3}>Why this is suspicious</Heading><span>Evidence-grounded analysis</span></div></div>
            <ul className="reason-list">
              {incidentEvidence.slice(0, 4).map((item, index) => <li key={item.id}><span>{index + 1}</span><p>{item.detail} <code>{item.id}</code></p></li>)}
            </ul>
            <button className="analysis-link" onClick={() => onTabChange("AI Analysis")}><Icon name="spark" size={15} />Open full AI analysis<Icon name="chevron" size={14} /></button>
          </section>
          <section className="panel action-card">
            <div className="summary-card__title"><Icon name="shield" size={17} /><div><Heading level={3}>Recommended actions</Heading><span>Prioritized response plan</span></div></div>
            {(currentInvestigation?.recommendations ?? []).map((action, index) => <label className="action-item" key={action}><input type="checkbox" /><span><b>{index + 1}</b>{action}</span></label>)}
            <Button variant="secondary">Create response case</Button>
          </section>
        </aside>
      </div>
      </>}
      {activeTab === "Timeline" && <InvestigationTimeline items={timelineItems} />}
      {activeTab === "Attack Graph" && <AttackGraph embedded incidentId={incidentId} />}
      {activeTab === "Evidence" && <InvestigationEvidence items={incidentEvidence} stageCards={stageCards} />}
      {activeTab === "Entities" && <InvestigationEntities incidentId={incidentId} />}
      {activeTab === "AI Analysis" && <AIAnalysis inline investigationId={incidentId} />}
    </div>
  );
}

function Claim({ children, ids }: { children: ReactNode; ids: string[] }) {
  return <li><span className="claim-check"><Icon name="check" size={12} /></span><p>{children} <span className="claim-refs">{ids.map((id) => <code key={id}>{id}</code>)}</span></p></li>;
}

function AIAnalysis({ onClose, inline = false, investigationId = "" }: { onClose?: () => void; inline?: boolean; investigationId?: string }) {
  const { currentInvestigation } = useCerberusData();
  const [analysisData, setAnalysisData] = useState<AIAnalysis | null>(null);
  const [analysisLoading, setAnalysisLoading] = useState(true);
  const [analysisError, setAnalysisError] = useState("");
  const aiDisabled = (() => {
    try {
      const stored = window.localStorage.getItem("cerberus-settings");
      return stored ? JSON.parse(stored).aiEnabled === false : false;
    } catch {
      return false;
    }
  })();
  useEffect(() => {
    if (aiDisabled) {
      setAnalysisLoading(false);
      return;
    }
    setAnalysisLoading(true);
    aiService.getAIAnalysis(investigationId).then(setAnalysisData).catch((error: unknown) => {
      setAnalysisError(error instanceof Error ? error.message : "Unable to generate analysis");
    }).finally(() => setAnalysisLoading(false));
  }, [investigationId, aiDisabled]);
  if (aiDisabled) return <aside className={`ai-drawer ${inline ? "ai-drawer--inline panel" : ""}`}><div className="ai-drawer__head"><div className="ai-title"><div><Icon name="spark" size={20} /></div><div><span>AI Incident Analysis</span><small>Disabled in Settings</small></div></div></div><div className="ai-content"><p className="muted">AI analysis is currently disabled. Enable it in Settings to generate an evidence-grounded explanation.</p></div></aside>;
  if (analysisLoading) return <aside className={`ai-drawer ${inline ? "ai-drawer--inline panel" : ""}`}><div className="ai-drawer__head"><div className="ai-title"><div><Icon name="spark" size={20} /></div><div><span>AI Incident Analysis</span><small>Loading evidence-grounded analysis…</small></div></div></div><div className="ai-content"><p className="muted">Preparing analysis from verified investigation evidence.</p></div></aside>;
  const analysisSummary = analysisData?.summary ?? "No analysis is available for this investigation.";
  const analysisReasons = analysisData?.whySuspicious ?? [];
  const analysisProgression = analysisData?.attackProgression ?? currentInvestigation?.stages.map(displayStage) ?? [];
  const analysisRecommendations = analysisData?.recommendations ?? [];
  const confidencePercent = Math.round((currentInvestigation?.confidence ?? 0) * 100);
  const analysis = (
      <aside className={`ai-drawer ${inline ? "ai-drawer--inline panel" : ""}`} onMouseDown={(event) => event.stopPropagation()}>
        <div className="ai-drawer__head"><div className="ai-title"><div><Icon name="spark" size={20} /></div><div><span>AI Incident Analysis</span><small>On-device model · Evidence grounded</small></div></div>{!inline && <button className="icon-button" onClick={onClose} aria-label="Close analysis"><Icon name="close" size={18} /></button>}</div>
        <div className="ai-grounding"><Icon name="shield" size={16} /><div><strong>Auditable analysis</strong><span>Evidence references are drawn from this investigation.</span></div><Badge tone="low">{analysisData?.evidenceReferences.length ?? 0} references</Badge></div>
        <div className="ai-content">
          {analysisError && <p role="alert">{analysisError}</p>}
          <section><div className="ai-section-label"><span>01</span>What happened?</div><p className="ai-summary">{analysisSummary} <code>{analysisData?.evidenceReferences.join(" ")}</code></p></section>
          <section><div className="ai-section-label"><span>02</span>Why is it suspicious?</div><ul className="claim-list">{analysisReasons.map((reason, index) => <Claim key={reason} ids={analysisData?.evidenceReferences.slice(index, index + 1) ?? []}>{reason}</Claim>)}</ul></section>
          <section><div className="ai-section-label"><span>03</span>Attack progression</div><div className="ai-progression">{analysisProgression.map((stage, i) => <div key={stage}><span>{i + 1}</span><strong>{stage}</strong>{i < analysisProgression.length - 1 && <Icon name="chevron" size={14} />}</div>)}</div></section>
          <section><div className="ai-section-label"><span>04</span>Analysis confidence</div><div className="ai-confidence"><div><strong>{confidencePercent}%</strong><span>Reconstruction confidence</span></div><div className="large-confidence-bar"><i style={{ width: `${confidencePercent}%` }} /></div><p>Confidence is based on the generated attack-chain record.</p></div></section>
          <section><div className="ai-section-label"><span>05</span>Recommended actions</div><ol className="ai-actions">{analysisRecommendations.map((recommendation, index) => <li key={recommendation}><span>{index === 0 ? "Immediate" : "Next"}</span><strong>{recommendation}</strong></li>)}</ol></section>
        </div>
        <div className="ai-drawer__footer"><span><span className="status-dot status-dot--green" />Analysis provider: {analysisData?.provider ?? "Cerberus"}</span><Button>Create response plan</Button></div>
      </aside>
  );

  if (inline) return analysis;
  return (
    <div className="drawer-backdrop" onMouseDown={onClose}>
      {analysis}
    </div>
  );
}

function Node({ className, type, title, subtitle, risk, onClick }: { className: string; type: IconName; title: string; subtitle: string; risk?: boolean; onClick?: () => void }) {
  return <button className={`graph-node ${className} ${risk ? "is-risky" : ""}`} onClick={onClick}><span className="graph-node__icon"><Icon name={type} size={18} /></span><span><small>{subtitle}</small><strong>{title}</strong></span>{risk && <span className="risk-pip" />}</button>;
}

function AttackGraph({ embedded = false, incidentId = "" }: { embedded?: boolean; incidentId?: string }) {
  const { investigations, graph, entities } = useCerberusData();
  const incident = investigations.find((row) => row.id === incidentId);
  const typeOrder: Record<string, number> = { User: 0, Device: 1, USBActivity: 2, File: 3, Event: 4 };
  const graphNodes = [...graph.nodes]
    .sort((left, right) => (typeOrder[left.type] ?? 5) - (typeOrder[right.type] ?? 5))
    .slice(0, 8);
  const [selected, setSelected] = useState(graphNodes[0]?.id ?? "");
  useEffect(() => setSelected(graphNodes[0]?.id ?? ""), [incidentId, graph.nodes]);
  const selectedEntity = entities.find((entity) => entity.entity_id === selected);
  const relatedIds = new Set(graph.edges.filter((edge) => edge.source === selected || edge.target === selected).flatMap((edge) => [edge.source, edge.target]));
  const relatedNodes = graph.nodes.filter((node) => relatedIds.has(node.id) && node.id !== selected).slice(0, 8);
  const iconFor = (type: string): IconName =>
    type === "User" ? "entities" : type === "Device" ? "server" : type === "Event" ? "evidence" : type === "File" ? "file" : type === "USBActivity" ? "usb" : "target";
  const nodeClasses = ["node-user", "node-device", "node-file", "node-usb", "node-ip", "node-okta", "node-folder", "node-process"];
  const points = [
    [180, 180],
    [360, 270],
    [600, 270],
    [815, 180],
    [815, 480],
    [245, 480],
    [555, 480],
    [805, 465],
  ];
  const visibleNodeIds = new Set(graphNodes.map((node) => node.id));
  const visibleEdges = graph.edges.filter((edge) => visibleNodeIds.has(edge.source) && visibleNodeIds.has(edge.target));
  const selectedRisk = incident?.risk_score ?? 0;
  return (
    <div className={embedded ? "investigation-subview" : "page page--graph"}>
      <div className="page-heading graph-heading"><div><div className="eyebrow">Incident {incidentId}</div><Heading level={1}>Attack Graph</Heading><p>Observed entities and relationships for {incident?.title ?? "this investigation"}.</p></div><div className="graph-heading__actions"><Button variant="secondary" icon="filter">Graph filters</Button><Button icon="target">Highlight attack path</Button></div></div>
      <div className="graph-legend"><span><i className="node-dot node-dot--user" />User</span><span><i className="node-dot node-dot--device" />Device</span><span><i className="node-dot node-dot--event" />Event / Artifact</span><span><i className="node-dot node-dot--external" />Other</span><span className="legend-path"><i />Observed relationships</span><Badge tone="high" dot>{graph.nodes.length} graph entities</Badge></div>
      <div className="graph-workspace">
        <div className="graph-canvas">
          <svg className="graph-lines" viewBox="0 0 1000 650" preserveAspectRatio="none" aria-label="Observed entity relationship edges">
            {visibleEdges.map((edge, index) => {
              const sourceIndex = graphNodes.findIndex((node) => node.id === edge.source);
              const targetIndex = graphNodes.findIndex((node) => node.id === edge.target);
              const [x1, y1] = points[sourceIndex];
              const [x2, y2] = points[targetIndex];
              return <path key={`${edge.source}-${edge.target}-${index}`} d={`M ${x1} ${y1} C ${(x1 + x2) / 2} ${y1}, ${(x1 + x2) / 2} ${y2}, ${x2} ${y2}`}><title>{`${edge.source} ${edge.relationship} ${edge.target}`}</title></path>;
            })}
          </svg>
          {graphNodes.map((node, index) => <Node key={node.id} className={nodeClasses[index]} type={iconFor(node.type)} title={node.label ?? node.id} subtitle={node.type.toUpperCase()} risk={selectedRisk >= 70} onClick={() => setSelected(node.id)} />)}
          {!graphNodes.length && <div className="queue-empty">No graph nodes are available for this investigation.</div>}
          <div className="graph-controls"><Button variant="icon" icon="zoomIn" ariaLabel="Zoom in" /><Button variant="icon" icon="zoomOut" ariaLabel="Zoom out" /><Button variant="icon" icon="target" ariaLabel="Center graph" /></div>
          <div className="graph-minimap"><div><i /><i /><i /><i /><i /></div><span>Overview</span></div>
        </div>
        <aside className="entity-detail">
          <div className="entity-detail__head"><Badge tone={selectedRisk >= 70 ? "high" : "medium"} dot>{selectedRisk ? `${selectedRisk} risk score` : "Observed"}</Badge><Button variant="icon" icon="close" ariaLabel="Close entity details" /></div>
          <div className="entity-hero"><div className="entity-hero__icon"><Icon name={iconFor(graph.nodes.find((node) => node.id === selected)?.type ?? "Event")} size={24} /></div><span>{selectedEntity?.entity_type ?? graph.nodes.find((node) => node.id === selected)?.type ?? "Entity"}</span><Heading level={2}>{selectedEntity?.name ?? selected}</Heading></div>
          <div className="risk-score"><div><span>Incident risk score</span><strong>{selectedRisk}<small>/100</small></strong></div><div className="risk-meter"><i style={{ width: `${selectedRisk}%` }} /></div><p>Score from the reconstructed incident record.</p></div>
          <div className="entity-section"><Heading level={3}>Entity details</Heading><dl><div><dt>Entity ID</dt><dd className="mono">{selected || "—"}</dd></div><div><dt>Context</dt><dd>{selectedEntity?.context ?? "No registry details available"}</dd></div><div><dt>Type</dt><dd>{selectedEntity?.entity_type ?? graph.nodes.find((node) => node.id === selected)?.type ?? "—"}</dd></div><div><dt>Related events</dt><dd>{selectedEntity?.related_event_ids.length ?? 0}</dd></div></dl></div>
          <div className="entity-stats"><div><strong>{selectedEntity?.related_event_ids.length ?? 0}</strong><span>Events</span></div><div><strong>{relatedNodes.length}</strong><span>Relations</span></div><div><strong>{incident?.stages.length ?? 0}</strong><span>Stages</span></div></div>
          <div className="entity-section"><div className="section-row"><Heading level={3}>Connected entities</Heading><span>{relatedNodes.length} total</span></div>{relatedNodes.map((node) => <div className="related-entity" key={node.id}><span className="related-icon"><Icon name="link" size={14} /></span><strong>{node.id} · {node.type}</strong><Icon name="chevron" size={13} /></div>)}</div>
          <div className="entity-section"><div className="section-row"><Heading level={3}>Observed links</Heading><span>{graph.edges.length} edges</span></div>{graph.edges.slice(0, 5).map((edge, index) => <div className="related-entity" key={`${edge.source}-${edge.target}-${index}`}><span className="related-icon"><Icon name="link" size={14} /></span><strong>{edge.source} → {edge.target} · {edge.relationship}</strong></div>)}</div>
        </aside>
      </div>
    </div>
  );
}

type InvestigationRow = [string, string, string, string, string, string, string, string, string];

function investigationRows(records: InvestigationRecord[]): InvestigationRow[] {
  return records.map((item) => [
    item.id,
    item.title,
    item.severity,
    item.user_name ?? item.user_id ?? "Unknown user",
    item.device_name ?? item.device_id ?? "Unknown device",
    item.start_time.replace("T", " "),
    item.duration,
    `${Math.round(item.confidence * 100)}%`,
    item.status,
  ]);
}

function Investigations({ onOpen, threatHistory }: { onOpen: (incidentId: string) => void; threatHistory: Threat[] }) {
  const { investigations } = useCerberusData();
  const rowsSource = investigationRows(investigations);
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("All");
  const [status, setStatus] = useState("All");
  const [attackType, setAttackType] = useState("All");
  const rows = rowsSource.filter((row) => `${row[0]} ${row[1]} ${row[3]} ${row[4]}`.toLowerCase().includes(search.toLowerCase()))
    .filter((row) => severity === "All" || row[2] === severity)
    .filter((row) => status === "All" || (threatHistory.find((threat) => threat.id === row[0])?.status ?? row[8]) === status)
    .filter((row) => attackType === "All" || row[1] === attackType);
  const attackTypes = [...new Set(rowsSource.map((row) => row[1]))];
  return (
    <div className="page">
      <div className="page-heading"><div><div className="eyebrow">Attack reconstruction</div><Heading level={1}>Investigations</Heading><p>Reconstructed incidents prioritized by risk, confidence, and business impact.</p></div><Button>Create investigation</Button></div>
      <div className="filterbar"><label><Icon name="search" size={16} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search investigations…" /></label><select value={severity} onChange={(event) => setSeverity(event.target.value)}><option>All</option><option>Critical</option><option>High</option><option>Medium</option></select><select value={attackType} onChange={(event) => setAttackType(event.target.value)}><option>All</option>{attackTypes.map((type) => <option key={type}>{type}</option>)}</select><select value={status} onChange={(event) => setStatus(event.target.value)}><option>All</option><option>Active</option><option>Investigating</option><option>Completed</option></select><span>{rows.length} investigations</span></div>
      <div className="panel investigations-table"><table><thead><tr>{["Incident ID", "Attack Type", "Severity", "User", "Device", "Start Time", "Duration", "Confidence", "Status", ""].map((h) => <th key={h}>{h}</th>)}</tr></thead><tbody>{rows.map((row) => {
        const currentStatus = threatHistory.find((threat) => threat.id === row[0])?.status ?? row[8];
        return <tr key={row[0]} onClick={() => onOpen(row[0])}>{row.map((cell, i) => <td key={i}>{i === 0 ? <strong className="mono table-link">{cell}</strong> : i === 2 ? <Badge tone={cell.toLowerCase() as "critical" | "high" | "medium"}>{cell}</Badge> : i === 8 ? <span className="table-status"><span className={`status-dot status-dot--${currentStatus === "Resolved" ? "green" : "blue"}`} />{currentStatus}</span> : i === 7 ? <strong>{cell}</strong> : cell}</td>)}<td><Icon name="chevron" size={14} /></td></tr>;
      })}</tbody></table></div>
    </div>
  );
}

function Toggle({ checked, onChange, label }: { checked: boolean; onChange: (checked: boolean) => void; label: string }) {
  return <button className={`toggle ${checked ? "is-on" : ""}`} onClick={() => onChange(!checked)} role="switch" aria-checked={checked} aria-label={label}><span /></button>;
}

function SettingsScreen({ demoMode, simulationRunning, demoScenario, onDemoMode, onDemoScenario, onResetSimulation }: { demoMode: boolean; simulationRunning: boolean; demoScenario: SimulationScenario; onDemoMode: (enabled: boolean) => void; onDemoScenario: (scenario: SimulationScenario, applyToRunning?: boolean) => void; onResetSimulation: () => void }) {
  const { dashboard } = useCerberusData();
  const [aiEnabled, setAiEnabled] = useState(true);
  const [evidenceRefs, setEvidenceRefs] = useState(true);
  const [remediation, setRemediation] = useState(true);
  const [confidence, setConfidence] = useState(85);
  const [sensitivity, setSensitivity] = useState("High");
  const [severity, setSeverity] = useState("High");
  const [sourceNames, setSourceNames] = useState<string[]>([]);
  const [sourceAvailability, setSourceAvailability] = useState<Record<string, boolean>>({});
  const [sources, setSources] = useState<boolean[]>([]);
  const [ollamaAvailable, setOllamaAvailable] = useState(false);
  const [settingsError, setSettingsError] = useState("");
  const [popup, setPopup] = useState(true);
  const [criticalAlerts, setCriticalAlerts] = useState(true);
  const [highAlerts, setHighAlerts] = useState(true);
  const [mediumAlerts, setMediumAlerts] = useState(false);
  const [sound, setSound] = useState(false);
  const [darkMode, setDarkMode] = useState(true);
  const [compact, setCompact] = useState(true);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    let alive = true;
    settingsService.getSettings().then((settings) => {
      if (!alive) return;
      const rows = Object.entries(settings.data_sources);
      setSourceNames(rows.map(([name]) => name));
      setSourceAvailability(Object.fromEntries(rows.map(([name, source]) => [name, Boolean(source)])));
      setSources(rows.map(([, source]) => Boolean(source)));
      setOllamaAvailable(settings.ollama_available);
      setSettingsError("");
    }).catch((error: unknown) => {
      if (alive) setSettingsError(error instanceof Error ? error.message : "Unable to load backend settings");
    });
    return () => { alive = false; };
  }, []);

  useEffect(() => {
    const stored = window.localStorage.getItem("cerberus-settings");
    if (!stored) return;
    try {
      const settings = JSON.parse(stored) as { aiEnabled?: boolean; confidence?: number; sensitivity?: string; severity?: string };
      if (typeof settings.aiEnabled === "boolean") setAiEnabled(settings.aiEnabled);
      if (typeof settings.confidence === "number") setConfidence(settings.confidence);
      if (settings.sensitivity) setSensitivity(settings.sensitivity);
      if (settings.severity) setSeverity(settings.severity);
    } catch {
      window.localStorage.removeItem("cerberus-settings");
    }
  }, []);

  const reset = () => {
    setAiEnabled(true); setEvidenceRefs(true); setRemediation(true); setConfidence(85); setSensitivity("High"); setSeverity("High");
    setSources(sourceNames.map((name) => sourceAvailability[name] ?? false)); setPopup(true); setCriticalAlerts(true); setHighAlerts(true); setMediumAlerts(false); setSound(false);
    setDarkMode(true); setCompact(true); onDemoMode(false); onDemoScenario("INSIDER_THEFT", false); setSaved(false);
  };

  const save = () => {
    window.localStorage.setItem("cerberus-settings", JSON.stringify({ aiEnabled, confidence, sensitivity, severity, demoMode, demoScenario }));
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  };

  return (
    <div className="page settings-page">
      <div className="page-heading"><div><div className="eyebrow">Security Operations</div><Heading level={1}>Settings</Heading><p>Configure detection, local AI analysis, event sources, and analyst preferences.</p></div><div className="settings-actions"><Button variant="ghost" onClick={reset}>Reset to Defaults</Button><Button onClick={save}>Save Changes</Button></div></div>
      <div className="settings-layout">
        <aside className="panel settings-nav">{["General", "Detection", "AI Assistant", "Data Sources", "Alerts", "Appearance", "Demo Mode"].map((item, index) => <button className={index === 0 ? "is-active" : ""} key={item}>{item}</button>)}</aside>
        <div className="settings-content">
          <section className="panel settings-section">
            <div className="settings-section__head"><div><Heading level={2}>General</Heading><p>Workspace identity and localization preferences.</p></div></div>
            <div className="settings-grid"><label><span>Organization</span><input value="Cerberus Financial" readOnly /></label><label><span>Environment</span><select defaultValue="Production"><option>Production</option><option>Staging</option></select></label><label><span>Time zone</span><select defaultValue="UTC"><option>UTC</option><option>Local time</option></select></label><label><span>Date/time format</span><select defaultValue="24-hour"><option>24-hour</option><option>12-hour</option></select></label></div>
          </section>
          <section className="panel settings-section">
            <div className="settings-section__head"><div><Heading level={2}>Detection</Heading><p>Control which reconstructed threats enter the active queue.</p></div></div>
            <div className="setting-row"><div><strong>Detection Sensitivity</strong><span>Adjust correlation sensitivity across connected sources.</span></div><div className="segmented">{["Low", "Medium", "High"].map((level) => <button className={sensitivity === level ? "is-active" : ""} onClick={() => setSensitivity(level)} key={level}>{level}</button>)}</div></div>
            <div className="setting-row"><div><strong>Minimum Confidence Threshold</strong><span>Only reconstructed attacks above this confidence create threats.</span></div><label className="range-control"><input type="range" min="50" max="100" value={confidence} onChange={(event) => setConfidence(Number(event.target.value))} /><b>{confidence}%</b></label></div>
            <div className="setting-row"><div><strong>Alert Severity Threshold</strong><span>Minimum severity level required to create an active threat.</span></div><select value={severity} onChange={(event) => setSeverity(event.target.value)}><option>Critical</option><option>High</option><option>Medium</option><option>Low</option></select></div>
          </section>
          <section className="panel settings-section">
            <div className="settings-section__head"><div><Heading level={2}>AI Assistant</Heading><p>Ollama explains verified reconstruction data when available; otherwise analysis is generated from incident records.</p></div><Badge tone={aiEnabled ? "low" : "neutral"} dot>{aiEnabled ? (ollamaAvailable ? "Ollama available" : "Evidence-based") : "Disabled"}</Badge></div>
            <div className="ai-runtime"><div><Icon name="spark" size={18} /><span><strong>AI Incident Analysis</strong><small>Runtime: {ollamaAvailable ? "Ollama" : "Evidence-based fallback"}</small></span></div><Toggle checked={aiEnabled} onChange={setAiEnabled} label="Enable AI explanations" /></div>
            <div className="setting-row"><div><strong>Show evidence references</strong><span>Attach verified event IDs to every generated claim.</span></div><Toggle checked={evidenceRefs} onChange={setEvidenceRefs} label="Show evidence references" /></div>
            <div className="setting-row"><div><strong>Remediation recommendations</strong><span>Include evidence-based response guidance.</span></div><Toggle checked={remediation} onChange={setRemediation} label="Enable remediation recommendations" /></div>
            <div className="setting-row"><div><strong>Explanation detail level</strong><span>Control the amount of supporting analysis shown.</span></div><select defaultValue="Analyst"><option>Concise</option><option>Analyst</option><option>Detailed</option></select></div>
          </section>
          <section className="panel settings-section">
            <div className="settings-section__head"><div><Heading level={2}>Data Sources</Heading><p>Persisted Cerberus artifacts used by the API.</p></div><Badge tone="blue">{sources.filter(Boolean).length} available</Badge></div>
            <div className="source-list">{settingsError && <p role="alert">{settingsError}</p>}{sourceNames.map((name, index) => <div className="source-row" key={name}><span className="source-row__icon"><Icon name="database" size={15} /></span><div><strong>{name}</strong><span><span className={`status-dot status-dot--${sourceAvailability[name] ? "green" : "blue"}`} />{sourceAvailability[name] ? "Available" : "Unavailable"}</span></div><div><span>Events processed</span><strong>{name === "events" ? dashboard?.events_processed ?? "—" : "—"}</strong></div><div><span>Source</span><strong>{sourceAvailability[name] ? "Configured" : "Missing"}</strong></div><Toggle checked={sources[index] ?? false} onChange={(enabled) => setSources((current) => current.map((value, itemIndex) => itemIndex === index ? enabled : value))} label={`Enable ${name}`} /></div>)}</div>
          </section>
          <section className="panel settings-section">
            <div className="settings-section__head"><div><Heading level={2}>Alerts</Heading><p>Choose which threat detections interrupt the analyst workflow.</p></div></div>
            {[["Enable threat popup", popup, setPopup], ["Critical alerts", criticalAlerts, setCriticalAlerts], ["High-risk alerts", highAlerts, setHighAlerts], ["Medium-risk alerts", mediumAlerts, setMediumAlerts], ["Notification sound", sound, setSound]].map(([label, checked, setter]) => <div className="setting-row" key={String(label)}><div><strong>{String(label)}</strong></div><Toggle checked={checked as boolean} onChange={setter as (checked: boolean) => void} label={String(label)} /></div>)}
            <div className="setting-row"><div><strong>Auto-dismiss behavior</strong><span>Threat alerts remain visible by default.</span></div><select defaultValue="Never"><option>Never</option><option>After 30 seconds</option><option>After 1 minute</option></select></div>
          </section>
          <section className="panel settings-section">
            <div className="settings-section__head"><div><Heading level={2}>Appearance</Heading><p>Display density preferences for the investigation workspace.</p></div></div>
            <div className="setting-row"><div><strong>Dark mode</strong><span>Optimized for security operations environments.</span></div><Toggle checked={darkMode} onChange={setDarkMode} label="Dark mode" /></div>
            <div className="setting-row"><div><strong>Compact analyst view</strong><span>Show more security context within the workspace.</span></div><Toggle checked={compact} onChange={setCompact} label="Compact analyst view" /></div>
            <div className="setting-row"><div><strong>Graph density</strong><span>Default number of related entities displayed.</span></div><select defaultValue="Balanced"><option>Focused</option><option>Balanced</option><option>Expanded</option></select></div>
          </section>
          <section className="panel settings-section demo-section">
            <div className="settings-section__head"><div><Heading level={2}>Demo Mode</Heading><p>Populate a controlled end-to-end attack scenario for reliable demonstrations.</p><span className="muted">{simulationRunning ? "Simulation running" : "Simulation stopped"}</span></div><Toggle checked={demoMode} onChange={onDemoMode} label="Demo Mode" /></div>
            <div className="setting-row"><div><strong>Attack scenario</strong><span>Choose the scenario played continuously while Demo Mode is enabled.</span></div><select value={demoScenario} onChange={(event) => onDemoScenario(event.target.value as SimulationScenario)} disabled={!demoMode}><option value="INSIDER_THEFT">Insider data theft</option><option value="MALWARE_INFECTION">Malware infection</option><option value="LATERAL_MOVEMENT">Lateral movement</option></select></div>
            <div className="section-heading"><Button onClick={() => onDemoMode(!simulationRunning)}>{simulationRunning ? "Stop Simulation" : "Start Simulation"}</Button><Button variant="secondary" onClick={onResetSimulation}>Reset Demo Data</Button></div>
            <div className="demo-flow">{["Threat Alert", "Active Threat", "Investigation", "Timeline", "Entity Graph", "Evidence", "Ollama Explanation", "Resolution"].map((step, index) => <span key={step}><b>{step}</b>{index < 7 && <Icon name="chevron" size={12} />}</span>)}</div>
          </section>
        </div>
      </div>
      {saved && <div className="toast"><Icon name="check" size={15} />Settings updated successfully</div>}
    </div>
  );
}

function Reports({ reports, onOpen }: { reports: ReportModel[]; onOpen: (incidentId: string) => void }) {
  const [selectedReport, setSelectedReport] = useState<ReportModel | null>(null);
  const [search, setSearch] = useState("");
  const filtered = reports.filter((report) => `${report.id} ${report.title} ${report.investigationId}`.toLowerCase().includes(search.toLowerCase()));
  return (
    <div className="page">
      <div className="page-heading"><div><div className="eyebrow">Security Operations</div><Heading level={1}>Investigation Reports</Heading><p>Auditable incident findings, evidence summaries, and response records.</p></div><Button variant="secondary" icon="filter">Filters</Button></div>
      <div className="filterbar"><label><Icon name="search" size={16} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search reports…" /></label><span>{filtered.length} reports</span></div>
      <div className="panel investigations-table reports-table"><table><thead><tr><th>Report ID</th><th>Incident ID</th><th>Report</th><th>Attack type</th><th>Created</th><th>Status</th><th /></tr></thead><tbody>{filtered.map((report) => <tr key={report.id} onClick={() => setSelectedReport(report)}><td><strong className="mono table-link">{report.id}</strong></td><td><strong className="mono table-link">{report.investigationId}</strong></td><td><strong>{report.title}</strong></td><td>{report.attackType}</td><td>{new Date(report.createdAt).toLocaleDateString()}</td><td><span className="table-status"><span className={`status-dot status-dot--${report.status === "Final" ? "green" : "blue"}`} />{report.status}</span></td><td><Icon name="chevron" size={14} /></td></tr>)}</tbody></table>{!filtered.length && <div className="queue-empty"><Icon name="report" size={22} /><Heading level={3}>No completed investigation reports yet</Heading><p>Generate a report from a completed investigation.</p></div>}</div>
      {selectedReport && <section className="panel report-detail">
        <div className="panel-title"><div><Heading level={2}>{selectedReport.title}</Heading><span>{selectedReport.id} · {selectedReport.investigationId}</span></div><Button variant="icon" icon="close" ariaLabel="Close report details" onClick={() => setSelectedReport(null)} /></div>
        <div className="detail-grid"><div><span>Executive Summary</span><strong>{selectedReport.executiveSummary}</strong></div><div><span>Overall Analysis</span><strong>{selectedReport.overallAnalysis}</strong></div><div><span>Forward Risk Assessment</span><strong>{selectedReport.forwardRiskAssessment}</strong></div><div><span>Final Assessment</span><strong>{selectedReport.finalAssessment}</strong></div></div>
        <div className="section-heading"><Heading level={3}>Attack Timeline</Heading><Button variant="ghost" onClick={() => onOpen(selectedReport.investigationId)}>Open investigation</Button></div>
        <div className="timeline-list">{selectedReport.timeline.map((event) => <div className="timeline-event" key={event.event_id}><span className="timeline-event__time">{event.timestamp.slice(11, 16)}</span><span className={`timeline-event__marker tone-${event.severity.toLowerCase()}`}><Icon name="evidence" size={15} /></span><span className="timeline-event__body"><strong>{event.event_type}</strong><small>{event.description}</small></span></div>)}</div>
        <div className="section-heading"><Heading level={3}>AI Incident Assessment</Heading></div><p>{selectedReport.aiAssessment}</p>
        <div className="section-heading"><Heading level={3}>Recommended Actions</Heading></div><ul>{selectedReport.recommendedActions.map((action) => <li key={action}>{action}</li>)}</ul>
      </section>}
    </div>
  );
}

function PlaceholderPage({ page, onOpen }: { page: Page; onOpen: () => void }) {
  const { investigations } = useCerberusData();
  const incident = investigations[0];
  const copy: Record<string, [string, string]> = {
    "Active Threats": ["Active Threats", "Live threats prioritized by reconstructed impact and confidence."],
  };
  const [title, subtitle] = copy[page] || [page, "Security operations workspace"];
  return <div className="page"><div className="page-heading"><div><div className="eyebrow">Security Operations</div><Heading level={1}>{title}</Heading><p>{subtitle}</p></div><Button variant="secondary" icon="filter">Filters</Button></div><div className="panel placeholder-panel"><div className="placeholder-icon"><Icon name={primaryNav.find((n) => n.label === page)?.icon || "shield"} size={28} /></div><Heading level={2}>{incident ? `Focused on incident ${incident.id}` : "No reconstructed incidents"}</Heading><p>{incident ? "Open an incident to review its timeline, evidence, entities, and analysis." : "The backend has not produced an incident record yet."}</p>{incident && <Button onClick={onOpen}>Open investigation</Button>}</div></div>;
}

const tabFromQuery = (value: string | null): InvestigationTab => {
  const tabs: Record<string, InvestigationTab> = {
    overview: "Overview",
    timeline: "Timeline",
    graph: "Attack Graph",
    evidence: "Evidence",
    entities: "Entities",
    ai: "AI Analysis",
  };
  return tabs[value ?? "overview"] ?? "Overview";
};

const readLocation = () => {
  const path = window.location.pathname;
  const investigationMatch = path.match(/^\/investigations\/([^/]+)$/);
  if (investigationMatch) {
    return { page: "Investigations" as Page, investigationOpen: true, incidentId: decodeURIComponent(investigationMatch[1]), tab: tabFromQuery(new URLSearchParams(window.location.search).get("tab")) };
  }
  const pages: Record<string, Page> = {
    "/": "Overview",
    "/active-threats": "Active Threats",
    "/investigations": "Investigations",
    "/reports": "Reports",
    "/settings": "Settings",
  };
  return { page: pages[path] ?? "Overview", investigationOpen: false, incidentId: "", tab: "Overview" as InvestigationTab };
};

const tabToQuery = (tab: InvestigationTab) => ({
  Overview: "overview",
  Timeline: "timeline",
  "Attack Graph": "graph",
  Evidence: "evidence",
  Entities: "entities",
  "AI Analysis": "ai",
}[tab]);

export default function App() {
  const initialLocation = readLocation();
  const storedDemoSettings = (() => {
    try {
      return JSON.parse(window.localStorage.getItem("cerberus-settings") ?? "{}") as {
        demoMode?: boolean;
        demoScenario?: SimulationScenario;
      };
    } catch {
      return {};
    }
  })();
  const [page, setPage] = useState<Page>(initialLocation.page);
  const [showAlert, setShowAlert] = useState(false);
  const [investigationOpen, setInvestigationOpen] = useState(initialLocation.investigationOpen);
  const [selectedIncident, setSelectedIncident] = useState(initialLocation.incidentId);
  const [activeTab, setActiveTab] = useState<InvestigationTab>(initialLocation.tab);
  const [investigationRecords, setInvestigationRecords] = useState<InvestigationRecord[]>([]);
  const [threatHistory, setThreatHistory] = useState<Threat[]>([]);
  const [reports, setReports] = useState<ReportModel[]>([]);
  const [dashboard, setDashboard] = useState<Awaited<ReturnType<typeof dashboardService.getDashboard>> | null>(null);
  const [currentInvestigation, setCurrentInvestigation] = useState<InvestigationRecord | null>(null);
  const [timeline, setTimeline] = useState<TimelineEntry[]>([]);
  const [evidenceEvents, setEvidenceEvents] = useState<CanonicalEvent[]>([]);
  const [entities, setEntities] = useState<Entity[]>([]);
  const [graph, setGraph] = useState<Graph>({ nodes: [], edges: [] });
  const [loading, setLoading] = useState(true);
  const [reportToast, setReportToast] = useState("");
  const [apiError, setApiError] = useState("");
  const [demoMode, setDemoMode] = useState(false);
  const [simulationRunning, setSimulationRunning] = useState(false);
  const [demoScenario, setDemoScenario] = useState<SimulationScenario>(
    storedDemoSettings.demoScenario ?? "INSIDER_THEFT",
  );
  const activeThreats = threatHistory.filter((threat) => threat.status !== "Resolved" && threat.status !== "False Positive");

  const toThreats = (records: InvestigationRecord[]): Threat[] =>
    records.map((item) => ({
      id: item.id,
      title: item.title,
      severity: item.severity as ThreatSeverity,
      status: item.status === "Active" ? "Investigating" : item.status === "Completed" || item.status === "Report Generated" ? "Resolved" : item.status === "False Positive" ? "False Positive" : item.status === "Contained" ? "Contained" : "Investigating",
      user: item.user_name ?? item.user_id ?? "Unknown user",
      device: item.device_name ?? item.device_id ?? "Unknown device",
      firstDetected: item.start_time.replace("T", " "),
      lastActivity: item.end_time.replace("T", " "),
      confidence: Math.round(item.confidence * 100),
      evidenceCount: item.evidence_count,
      stage: item.stages.at(-1) ? displayStage(item.stages.at(-1)) : "Investigation",
    }));

  useEffect(() => {
    let alive = true;
    const loadDashboard = async () => {
      try {
        const [result, liveEvents] = await Promise.all([
          dashboardService.getDashboard(),
          simulationService.getLiveEvents(8),
        ]);
        if (alive) {
          setDashboard({
            ...result,
            recent_events: liveEvents.items.length ? liveEvents.items : result.recent_events,
          });
          setApiError("");
        }
      } catch (error) {
        if (alive) setApiError(error instanceof Error ? error.message : "Unable to load dashboard data");
      }
    };
    let firstThreatLoad = true;
    let previousThreatIds = new Set<string>();
    const loadThreats = async () => {
      try {
        const pageResult = await threatService.getActiveThreats({ page: 1, page_size: 200 });
        if (alive) {
          const threats = toThreats(pageResult.items);
          setThreatHistory(threats);
          if (firstThreatLoad) {
            firstThreatLoad = false;
            if (initialLocation.page === "Overview" && !initialLocation.investigationOpen) setShowAlert(threats.length > 0);
          } else if (threats.some((threat) => !previousThreatIds.has(threat.id))) {
            setShowAlert(true);
          }
          previousThreatIds = new Set(threats.map((threat) => threat.id));
        }
      } catch (error) {
        if (alive) setApiError(error instanceof Error ? error.message : "Unable to load active threats");
      }
    };
    const loadInvestigations = async () => {
      try {
        const [result, liveIncidents] = await Promise.all([
          investigationService.getInvestigations(),
          simulationService.getLiveIncidents(200),
        ]);
        if (alive) {
          const byId = new Map(result.map((record) => [record.id, record]));
          for (const record of liveIncidents.items) byId.set(record.id, record);
          setInvestigationRecords([...byId.values()]);
          setSelectedIncident((current) =>
            byId.has(current) ? current : byId.values().next().value?.id ?? current,
          );
        }
      } catch (error) {
        if (alive) setApiError(error instanceof Error ? error.message : "Unable to load investigations");
      }
    };
    const loadReports = async () => {
      try {
        const result = await reportService.getReports();
        if (alive) setReports(result);
      } catch (error) {
        if (alive) setApiError(error instanceof Error ? error.message : "Unable to load reports");
      }
    };
    const loadSimulationStatus = async () => {
      try {
        const status = await simulationService.getStatus();
        if (!alive) return;
        setDemoMode(status.demo_mode);
        setSimulationRunning(status.running);
        if (status.demo_scenario) setDemoScenario(status.demo_scenario);
        if (status.last_error) setApiError(status.last_error);
      } catch (error) {
        if (alive) setApiError(error instanceof Error ? error.message : "Unable to load simulation status");
      }
    };
    void loadSimulationStatus();
    void Promise.all([loadDashboard(), loadThreats(), loadInvestigations(), loadReports()]).finally(() => {
      if (alive) setLoading(false);
    });
    const liveRefreshTimer = window.setInterval(() => {
      void loadDashboard();
      void loadThreats();
      void loadInvestigations();
      void loadReports();
      void loadSimulationStatus();
    }, 5_000);
    return () => {
      alive = false;
      window.clearInterval(liveRefreshTimer);
    };
  }, []);

  useEffect(() => {
    if (!investigationOpen || !selectedIncident) {
      setCurrentInvestigation(null);
      setTimeline([]);
      setEvidenceEvents([]);
      setEntities([]);
      setGraph({ nodes: [], edges: [] });
      return;
    }
    let alive = true;
    const loadDetails = async () => {
      try {
        const [record, timelineResult, evidenceResult, entityResult, graphResult] = await Promise.all([
          investigationService.getInvestigation(selectedIncident),
          investigationService.getTimeline(selectedIncident),
          investigationService.getEvidence(selectedIncident),
          investigationService.getEntities(selectedIncident),
          investigationService.getGraph(selectedIncident),
        ]);
        if (!alive) return;
        setCurrentInvestigation(record);
        setTimeline(timelineResult.timeline);
        setEvidenceEvents(evidenceResult);
        setEntities(entityResult);
        setGraph(graphResult);
        setApiError("");
      } catch (error) {
        if (alive) setApiError(error instanceof Error ? error.message : "Unable to load investigation details");
      }
    };
    void loadDetails();
    const detailTimer = window.setInterval(() => { void loadDetails(); }, 5_000);
    return () => { alive = false; window.clearInterval(detailTimer); };
  }, [investigationOpen, selectedIncident]);

  const goTo = (path: string) => {
    window.history.pushState({}, "", path);
    const location = readLocation();
    setPage(location.page);
    setInvestigationOpen(location.investigationOpen);
    setSelectedIncident(location.incidentId);
    setActiveTab(location.tab);
    setShowAlert(false);
  };

  useEffect(() => {
    const handlePopState = () => {
      const location = readLocation();
      setPage(location.page);
      setInvestigationOpen(location.investigationOpen);
      setSelectedIncident(location.incidentId);
      setActiveTab(location.tab);
    };
    window.addEventListener("popstate", handlePopState);
    return () => window.removeEventListener("popstate", handlePopState);
  }, []);

  const openInvestigation = (incidentId?: string) => {
    const targetIncident = incidentId ?? threatHistory[0]?.id ?? investigationRecords[0]?.id;
    if (!targetIncident) return;
    setShowAlert(false);
    goTo(`/investigations/${encodeURIComponent(targetIncident)}?tab=overview`);
  };

  const navigate = (next: Page) => {
    const paths: Record<Page, string> = {
      Overview: "/",
      "Active Threats": "/active-threats",
      Investigations: "/investigations",
      Reports: "/reports",
      Settings: "/settings",
    };
    goTo(paths[next]);
  };

  const navigateInvestigationTab = (tab: InvestigationTab) => {
    const incidentId = selectedIncident;
    goTo(`/investigations/${encodeURIComponent(incidentId)}?tab=${tabToQuery(tab)}`);
  };

  const updateThreatStatus = async (incidentId: string, status: ThreatStatus): Promise<void> => {
    try {
      const persistedStatus = status === "Resolved" ? "Completed" : status;
      await investigationService.updateStatus(incidentId, persistedStatus);
      setThreatHistory((current) => current.map((threat) => threat.id === incidentId ? { ...threat, status } : threat));
      setInvestigationRecords(await investigationService.getInvestigations());
      setApiError("");
    } catch (error) {
      setApiError(error instanceof Error ? error.message : "Unable to update investigation status");
      throw error;
    }
  };

  const updateDemoMode = async (enabled: boolean) => {
    setDemoMode(enabled);
    try {
      if (enabled) {
        await simulationService.start({ demo_mode: true, scenario: demoScenario });
      } else {
        await simulationService.stop();
      }
      setSimulationRunning(enabled);
      setApiError("");
    } catch (error) {
      setDemoMode(!enabled);
      setApiError(error instanceof Error ? error.message : "Unable to update Demo Mode");
    }
  };

  const toggleSimulation = async () => {
    try {
      if (simulationRunning) {
        await simulationService.stop();
        setSimulationRunning(false);
        setDemoMode(false);
      } else {
        await simulationService.start();
        setSimulationRunning(true);
        setDemoMode(false);
      }
      setApiError("");
      await Promise.all([
        dashboardService.getDashboard().then(setDashboard),
        investigationService.getInvestigations().then(setInvestigationRecords),
        threatService.getActiveThreats({ page: 1, page_size: 200 }).then((result) => setThreatHistory(toThreats(result.items))),
      ]);
    } catch (error) {
      setApiError(error instanceof Error ? error.message : "Unable to update simulation");
    }
  };

  const resetSimulation = async () => {
    try {
      const status = await simulationService.reset();
      setSimulationRunning(false);
      setDemoMode(false);
      setDashboard(null);
      setThreatHistory([]);
      setInvestigationRecords([]);
      setReports([]);
      setCurrentInvestigation(null);
      setTimeline([]);
      setEvidenceEvents([]);
      setEntities([]);
      setGraph({ nodes: [], edges: [] });
      setSelectedIncident("");
      setShowAlert(false);
      if (status.last_error) setApiError(status.last_error);
      else setApiError("");
    } catch (error) {
      setApiError(error instanceof Error ? error.message : "Unable to reset simulation data");
    }
  };

  const updateDemoScenario = async (scenario: SimulationScenario, applyToRunning = true) => {
    setDemoScenario(scenario);
    if (!demoMode || !applyToRunning) return;
    try {
      await simulationService.start({ demo_mode: true, scenario });
      setApiError("");
    } catch (error) {
      setApiError(error instanceof Error ? error.message : "Unable to change the Demo Mode scenario");
    }
  };

  const generateReport = async () => {
    const incidentId = selectedIncident;
    if (!investigationRecords.some((item) => item.id === incidentId)) return;
    setReportToast("Generating report…");
    try {
      const report = await reportService.generateReport(incidentId);
      setReports(await reportService.getReports());
      setReportToast(`Report ${report.id} generated successfully.`);
      setApiError("");
    } catch (error) {
      setReportToast("");
      setApiError(error instanceof Error ? error.message : "Unable to generate report");
    }
    setTimeout(() => setReportToast(""), 4000);
  };

  const contextValue = {
    dashboard,
    investigations: investigationRecords,
    currentInvestigation,
    timeline,
    timelineItems: toEvidenceItems(timeline, timeline),
    evidence: toEvidenceItems(evidenceEvents, timeline),
    entities,
    graph,
  };
  let content: ReactNode;
  if (investigationOpen) content = currentInvestigation ? <Investigation incidentId={selectedIncident} status={threatHistory.find((threat) => threat.id === selectedIncident)?.status ?? "Investigating"} activeTab={activeTab} onTabChange={navigateInvestigationTab} onBack={() => navigate("Investigations")} onGenerateReport={generateReport} /> : <div className="page"><div className="panel queue-empty">{apiError || "Loading investigation data…"}</div></div>;
  else if (page === "Overview") content = <Overview threats={activeThreats} onInvestigate={openInvestigation} onActiveThreats={() => navigate("Active Threats")} simulationRunning={simulationRunning} onToggleSimulation={toggleSimulation} onResetSimulation={resetSimulation} />;
  else if (page === "Active Threats") content = <ActiveThreats threats={activeThreats} onInvestigate={openInvestigation} onStatusChange={updateThreatStatus} />;
  else if (page === "Investigations") content = <Investigations onOpen={openInvestigation} threatHistory={threatHistory} />;
  else if (page === "Reports") content = <Reports reports={reports} onOpen={openInvestigation} />;
  else if (page === "Settings") content = <SettingsScreen demoMode={demoMode} simulationRunning={simulationRunning} demoScenario={demoScenario} onDemoMode={updateDemoMode} onDemoScenario={updateDemoScenario} onResetSimulation={resetSimulation} />;
  else content = <PlaceholderPage page={page} onOpen={() => openInvestigation()} />;

  return (
    <CerberusDataContext.Provider value={contextValue}>
      <div className="app-shell">
        <Sidebar page={page} setPage={navigate} activeThreatCount={activeThreats.length} />
        <div className="app-main"><Topbar page={investigationOpen ? "Investigations" : page} /><main>{apiError && <div className="toast" role="alert">{apiError}</div>}{content}</main></div>
        {showAlert && !loading && activeThreats[0] && <ThreatAlert threat={activeThreats[0]} onView={() => openInvestigation(activeThreats[0].id)} onDismiss={() => setShowAlert(false)} />}
        {reportToast && <div className="toast"><Icon name="check" size={15} />{reportToast}</div>}
      </div>
    </CerberusDataContext.Provider>
  );
}
