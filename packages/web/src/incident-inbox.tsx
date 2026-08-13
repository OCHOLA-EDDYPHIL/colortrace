import { StatusBadge } from "./status-badge.tsx";
import { Timestamp } from "./time.tsx";
import type { IncidentInboxItem } from "./view-state.ts";

export type IncidentInboxProps = {
  readonly incidents: readonly IncidentInboxItem[];
  readonly onSelectIncident?: (incidentId: string) => void;
  readonly selectedIncidentId: string | null;
};

export function IncidentInbox({
  incidents,
  onSelectIncident,
  selectedIncidentId,
}: IncidentInboxProps) {
  return (
    <nav aria-labelledby="incident-inbox-title" className="incident-inbox">
      <div className="section-heading">
        <div>
          <p className="eyebrow">Investigations</p>
          <h2 id="incident-inbox-title">Incident inbox</h2>
        </div>
        <span className="count-pill">
          <span aria-hidden="true">{incidents.length}</span>
          <span className="sr-only">{incidents.length} incidents</span>
        </span>
      </div>

      {incidents.length === 0 ? (
        <p className="empty-copy">No incidents are available.</p>
      ) : (
        <ul className="incident-list">
          {incidents.map((incident) => {
            const current = incident.id === selectedIncidentId;
            return (
              <li key={incident.id}>
                <a
                  aria-current={current ? "page" : undefined}
                  className="incident-list__button"
                  href={`/incidents/${encodeURIComponent(incident.id)}`}
                  onClick={(event) => {
                    if (onSelectIncident !== undefined) {
                      event.preventDefault();
                      onSelectIncident(incident.id);
                    }
                  }}
                >
                  <span className="incident-list__topline">
                    <strong>{incident.id}</strong>
                    <StatusBadge value={incident.status} />
                  </span>
                  <span className="incident-list__alert">Alert {incident.alert_id}</span>
                  <Timestamp value={incident.updated_at} />
                  {incident.delayed ? (
                    <span className="incident-list__delay">Delayed · investigation incomplete</span>
                  ) : null}
                </a>
              </li>
            );
          })}
        </ul>
      )}
    </nav>
  );
}
