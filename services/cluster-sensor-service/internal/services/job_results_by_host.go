package services

// A job's findings grouped by host ( H21, spec §1 "Job detail — results":
// "grouped by host → ports"). The flat results page by finding, 20 at a time
// and 100 at most, so a full-estate scan's results cost one call per twenty
// ports and a host's ports land on several pages. This pages by host.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
)

// hostKeySQL is what a finding is grouped by: its address, or the name it was
// scanned by when it never resolved.
const hostKeySQL = `COALESCE(host(resolved_ip), hostname, '')`

// jobHostsSQL is every host a job lists ($1 job, $2 tenant): each host with a
// finding, AND each address whose finished unit responded with nothing open
// (: a scan of a /24 said "25 responded" and listed 10 — the 15 that
// refused every port were nowhere, and the list read as broken paging). The
// second half is the coverage's own "responded" (unitRespondedSQL), so the
// list and the Coverage line cannot disagree; an address that never answered
// is not a host here. A unit address is cast to inet only when it looks like
// one (a zone-scoped or malformed address would fail the whole read) — the
// same "a name sorts after every address" rule then applies to it.
const jobHostsSQL = `
	SELECT ` + hostKeySQL + ` AS key, resolved_ip AS ip
	FROM discovery_findings WHERE job_id = $1 AND tenant_id = $2
	UNION ALL
	SELECT address AS key,
	       CASE WHEN address ~ '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' OR address ~ '^[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*$'
	            THEN address::inet END AS ip
	FROM discovery_job_units
	WHERE job_id = $1 AND tenant_id = $2 AND status = 'done' AND ` + unitRespondedSQL

// GetJobResultsByHost returns one page of a job's hosts, in address order,
// each with all its findings in port order. A scan-plan job's hosts that
// answered with nothing open are listed too, with no ports and NothingOpen set.
func (s *DiscoveryService) GetJobResultsByHost(tenantID, jobID string, page, pageSize int) (*models.DiscoveryResultsByHostResponse, error) {
	tenant, err := uuid.Parse(tenantID)
	if err != nil {
		return nil, fmt.Errorf("invalid tenant_id: %w", err)
	}
	resp := &models.DiscoveryResultsByHostResponse{JobID: jobID, Group: "host", Hosts: []models.DiscoveryHost{}, Page: page, PageSize: pageSize}
	err = s.withTenantTxx(context.Background(), tenant, func(tx *sqlx.Tx) error {
		if err := tx.Get(&resp.TotalHosts, `SELECT COUNT(DISTINCT key) FROM (`+jobHostsSQL+`) h`, jobID, tenant); err != nil {
			return fmt.Errorf("count hosts: %w", err)
		}
		var keys []string
		// Addresses sort as addresses (10.0.0.9 before 10.0.0.10); a name that
		// never resolved sorts after every address.
		if err := tx.Select(&keys, `
			SELECT key FROM (`+jobHostsSQL+`) h
			GROUP BY key
			ORDER BY MIN(ip) NULLS LAST, key
			LIMIT $3 OFFSET $4`, jobID, tenant, pageSize, (page-1)*pageSize); err != nil {
			return fmt.Errorf("list hosts: %w", err)
		}
		if len(keys) == 0 {
			return nil
		}
		type row struct {
			ID         string          `db:"id"`
			Key        string          `db:"key"`
			Hostname   sql.NullString  `db:"hostname"`
			Protocol   string          `db:"protocol"`
			Port       int             `db:"port"`
			Confidence sql.NullFloat64 `db:"confidence_score"`
			Details    []byte          `db:"details"`
		}
		var rows []row
		if err := tx.Select(&rows, `
			SELECT id, `+hostKeySQL+` AS key, hostname, protocol, port, confidence_score, details
			FROM discovery_findings
			WHERE job_id = $1 AND tenant_id = $2 AND `+hostKeySQL+` = ANY($3)
			ORDER BY port, protocol, id`, jobID, tenant, pq.Array(keys)); err != nil {
			return fmt.Errorf("read findings: %w", err)
		}
		type unitRow struct {
			Address        string         `db:"address"`
			Status         string         `db:"status"`
			Liveness       sql.NullString `db:"liveness_state"`
			Evidence       sql.NullString `db:"liveness_evidence"`
			PortsRequested int            `db:"ports_requested"`
			Open           int            `db:"open_count"`
			Closed         int            `db:"closed_count"`
			Filtered       int            `db:"filtered_count"`
			NotProbed      int            `db:"not_probed_count"`
			UDPAnswered    int            `db:"udp_answered_count"`
			Tarpit         bool           `db:"responds_on_all_ports"`
			OTSuspect      bool           `db:"ot_suspect"`
		}
		var units []unitRow
		if err := tx.Select(&units, `
			SELECT DISTINCT ON (address) address, status, liveness_state, liveness_evidence,
			       ports_requested, open_count, closed_count, filtered_count, not_probed_count, udp_answered_count,
			       responds_on_all_ports, ot_suspect
			FROM discovery_job_units WHERE job_id = $1 AND tenant_id = $2 AND address = ANY($3)
			ORDER BY address, finished_at DESC NULLS LAST`, jobID, tenant, pq.Array(keys)); err != nil {
			return fmt.Errorf("read units: %w", err)
		}
		hosts := make(map[string]*models.DiscoveryHost, len(keys))
		for _, k := range keys {
			hosts[k] = &models.DiscoveryHost{Address: k, Ports: []models.DiscoveryHostPort{}}
		}
		for _, u := range units {
			if h := hosts[u.Address]; h != nil {
				h.Unit = &models.DiscoveryHostUnit{
					Status: u.Status, LivenessState: u.Liveness.String, LivenessEvidence: u.Evidence.String, PortsRequested: u.PortsRequested,
					OpenCount: u.Open, ClosedCount: u.Closed, FilteredCount: u.Filtered, NotProbedCount: u.NotProbed,
					UDPAnsweredCount: u.UDPAnswered, RespondsOnAllPorts: u.Tarpit, OTSuspect: u.OTSuspect,
				}
			}
		}
		for _, r := range rows {
			h := hosts[r.Key]
			if h == nil {
				continue
			}
			if h.Hostname == "" && r.Hostname.Valid && r.Hostname.String != h.Address {
				h.Hostname = r.Hostname.String
			}
			data := map[string]interface{}{}
			if len(r.Details) > 0 {
				_ = json.Unmarshal(r.Details, &data)
			}
			p := models.DiscoveryHostPort{FindingID: r.ID, Port: r.Port, Protocol: r.Protocol, ConfidenceScore: r.Confidence.Float64, Data: data}
			p.Transport, _ = data["transport"].(string)
			p.ServiceHint, _ = data["service_hint"].(string)
			unidentified, _ := data["unidentified"].(bool)
			proto := strings.ToLower(r.Protocol)
			p.Identified = !unidentified && proto != "tcp" && proto != "udp"
			h.Ports = append(h.Ports, p)
		}
		for _, k := range keys {
			h := hosts[k]
			// Listed with no finding: it can only be here because its unit
			// responded (jobHostsSQL), i.e. it answered and nothing was open.
			h.NothingOpen = len(h.Ports) == 0
			resp.Hosts = append(resp.Hosts, *h)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return resp, nil
}
