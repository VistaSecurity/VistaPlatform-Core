package producers

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/findings/producer"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
)

// ConfigurationProducer is the `configuration` finding producer (ADR-0005 D3,
// workstream 3.5).
//
// It answers two questions from what the inventory already holds, against the
// rule table in configuration_rules.go:
//
//	is the MANAGEMENT PLANE in the clear?   → configuration/plaintext_management
//	is something UNSAFE EXPOSED?            → configuration/insecure_service_exposed
//
// # Two subjects for one kind, and why both
//
// `plaintext_management` is raised on the ASSET when the interrogation facts
// say so (`mgmt.plaintext` = true), and on the ENDPOINT when a specific socket
// is the plaintext management service. Those are different claims about
// different things — "this device is managed over Telnet" and "port 23 on this
// address answers Telnet" — and the registry allows both subject types for
// exactly that reason. One asset can carry both without collision:
// `findings_open_subject_uniq` is keyed on the subject, not on the kind alone.
//
// # `default_credentials_exposed` is registered and NOT produced
//
// The registry's third kind stays unimplemented, deliberately and not by
// omission. Nothing in the product records that a default credential was
// ACCEPTED: the interrogation collectors authenticate with credentials a tenant
// supplied and report success or failure of THAT, the cloud collectors use
// role-based access, and nothing anywhere tries a vendor default. A producer
// that raised the kind from, say, "this device answered on its management port"
// would be reporting an inference as a measurement, on the one kind whose whole
// content is "we tried it and it worked".
//
// The registry entry stays because the kind is real and the gap is worth being
// able to see. When a default-credential probe exists — an explicitly
// tenant-authorised one, per the active-probing scope rule — this is where it
// lands: one `Upsert` with the endpoint as its subject and the ACCOUNT NAME,
// never the credential, in evidence.
//
// # What it claims coverage of, and what it does not
//
// The pass records coverage (workstream 3.2's `producer_assessments`) for the
// assets it actually EXAMINED, which is narrower than the assets it read: an
// asset carrying no `mgmt.plaintext` fact AND no active endpoint gave this
// producer nothing to look at, and claiming it would turn "nothing was
// collected about this host" into "we looked and it is fine" on the
// `mgmt_plaintext` control. An asset with endpoints but no interrogation IS
// claimed — the rule table ran over every socket and answered — and so is one
// with an explicit `mgmt.plaintext: false`, because that is an answer.
//
// A loopback-bound endpoint still counts as examined: the pass looked at it and
// decided it is not an exposure, which is a judgement, not a gap.
//
// Coverage is written INSIDE the write transaction, so a pass that dies half
// way rolls the claim back with the findings that justify it.
type ConfigurationProducer struct {
	repo   *pgidentity.Repository
	writer *producer.Writer
}

// NewConfigurationProducer builds the producer over the RLS-subject handle.
//
// One handle, unlike the eol and vulnerability producers: this producer reads
// no platform catalogue. Its catalogue is the Go table beside it.
func NewConfigurationProducer(appDB *sql.DB) (*ConfigurationProducer, error) {
	w, err := producer.New(findings.ProducerConfiguration)
	if err != nil {
		return nil, err
	}
	return &ConfigurationProducer{
		repo:   pgidentity.New(appDB),
		writer: w,
	}, nil
}

// ConfigRun is one full pass over one tenant.
type ConfigRun struct {
	// Raised is how many findings were upserted (created or re-observed).
	Raised int
	// Resolved is how many the sweep moved to INACTIVE.
	Resolved int
	// Assets and Endpoints are how many of each the pass actually read. They
	// are logged even at zero findings because "nothing is misconfigured" and
	// "there was nothing to look at" are different answers, and an operator
	// reading the job log has no other way to tell them apart.
	Assets    int
	Endpoints int
	// MatchedByName and MatchedByPort split the raised findings by the strength
	// of the signal behind them. A pass whose findings are all port-derived is
	// a pass over an estate nothing has service-identified, which is a coverage
	// problem rather than a posture one.
	MatchedByName int
	MatchedByPort int
	// PlaintextAssessed counts assets carrying an explicit `mgmt.plaintext`
	// fact, either value. It is the coverage denominator: an asset with no such
	// fact has not been assessed for plaintext management, and reporting the
	// raised count alone would make an unassessed estate look clean.
	PlaintextAssessed int
	// Assessed is how many assets the pass claimed coverage of — the ones it
	// had something to look at. Strictly ≤ Assets: a host with no management
	// fact and no active endpoint is read and NOT claimed.
	Assessed int
	// FactsExpired counts assets whose management facts are past their
	// `asset_facts.expires_at` — read, not judged, and withheld from the sweep.
	// Reported rather than swallowed: a pass that quietly produced fewer
	// findings than yesterday's is one nobody can explain.
	FactsExpired int
	// EndpointsUnobserved counts endpoints this pass read but did not judge
	// because the hygiene pass has marked them `stale` — nothing has observed
	// the socket for the stale ladder's first rung. Same treatment as
	// FactsExpired, for the same reason: see configEndpoint.status.
	EndpointsUnobserved int
}

// configAsset is one asset the producer judges, with the management facts read
// off it.
type configAsset struct {
	id    uuid.UUID
	label string
	// mgmtPlaintext is three-valued: nil means no fact, which is NOT "false".
	// An explicit false is an answer (the device is managed over SSH or HTTPS)
	// and is counted as assessed; an absence is not assessed and is counted as
	// nothing at all.
	mgmtPlaintext *bool
	mgmtProtocol  string
	// factSource is the source_ref of the mgmt.plaintext fact — the citation.
	factSource string
	factSeenAt time.Time
	// factExpired is true when the newest `mgmt.*` fact has passed its
	// `asset_facts.expires_at`.
	//
	// The FOURTH state, and it is not the same as nil. nil is "nobody has
	// interrogated this device": there is nothing to judge and nothing to
	// resolve. Expired is "what an interrogation told us has run out": the
	// producer has stopped knowing, so it raises nothing AND withholds the
	// subject from the sweep, leaving a finding raised while the fact was
	// current exactly where it was. Resolving it would render "we stopped
	// knowing" as "somebody turned telnet off".
	factExpired bool

	endpoints []configEndpoint
}

// configEndpoint is one endpoint and the signals a rule may read off it.
type configEndpoint struct {
	id    uuid.UUID
	label string
	facts endpointFacts
	// boundLocal is three-valued, like the column. See the exposure guard in
	// planEndpoint.
	boundLocal *bool
	// status is `asset_endpoints.status`, and only `active` is judged.
	//
	// The read is `<> 'closed'` rather than `= 'active'` so a STALE endpoint is
	// still seen. That distinction is the whole point: `closed` is a host's
	// authoritative "this socket is gone", and a finding about it genuinely no
	// longer describes anything, so it is right to let the sweep resolve it.
	// `stale` says only that nothing has looked for thirty days. Dropping those
	// rows from the read would make the producer stop asserting their findings,
	// and a producer that stops asserting sweeps them INACTIVE — publishing
	// "no longer detected" on a Telnet port nobody turned off. So a stale
	// endpoint is planned for nothing and WITHHELD from the sweep, exactly as
	// an expired fact is (see configAsset.factExpired).
	status string
}

// Run executes the pass for one tenant.
//
// Read, plan, write — the same three phases as the eol producer, and the same
// rule: an error from the first two returns WITHOUT sweeping, because a pass
// that failed part way has not made a full statement about what it sees.
// There is no separate resolve phase here: the catalogue is a Go table, so
// planning needs no I/O at all.
func (p *ConfigurationProducer) Run(ctx context.Context, tenantID uuid.UUID) (ConfigRun, error) {
	var run ConfigRun

	subjects, err := p.read(ctx, tenantID)
	if err != nil {
		return ConfigRun{}, fmt.Errorf("configuration producer: reading tenant %s: %w", tenantID, err)
	}

	planned, assessed, withheld := p.plan(subjects, &run)

	if err := p.write(ctx, tenantID, planned, assessed, withheld, &run); err != nil {
		return ConfigRun{}, fmt.Errorf("configuration producer: writing tenant %s: %w", tenantID, err)
	}
	return run, nil
}

// read loads every asset the producer judges, its management facts and its
// endpoints.
//
// Archived and soft-deleted assets are excluded for the reason the eol producer
// excludes them: an archived asset is one the tenant decided to stop tracking,
// and raising fresh findings against it puts work back in a queue they emptied.
// Endpoints are narrowed to `status <> 'closed'`: a closed socket is a host's
// own statement that it is gone, so a finding about it describes the past and
// the sweep should resolve it. A STALE one is read but not judged — see
// configEndpoint.status.
func (p *ConfigurationProducer) read(ctx context.Context, tenantID uuid.UUID) ([]configAsset, error) {
	byID := map[uuid.UUID]*configAsset{}
	var order []uuid.UUID

	err := p.repo.RunInTx(ctx, tenantID.String(), func(r *pgidentity.Repository) error {
		tx := r.Tx()

		// One row per asset with the two mgmt.* facts folded in. DISTINCT ON
		// picks the most recently observed value per key — facts are stored per
		// SOURCE, so a device seen by both an interrogation and an agent has two
		// mgmt.protocol rows and something has to choose. Most-recent is the
		// honest default; full reconciliation precedence (ADR-0002 D4) belongs
		// to the asset read, not to a posture pass.
		//
		// `expires_at` travels with the value rather than filtering the CTE: an
		// expired fact and a fact that was never written are different answers,
		// and only one of them means "the condition is absent". See
		// configAsset.factExpired. The compliance fact shape already honours the
		// column (scope_probe.go); this producer did not.
		rows, err := tx.QueryContext(ctx, `
			WITH latest AS (
			    SELECT DISTINCT ON (asset_id, key) asset_id, key, value, source_ref, observed_at, expires_at
			    FROM asset_facts
			    WHERE tenant_id = $1 AND key = ANY($2::text[])
			    ORDER BY asset_id, key, observed_at DESC
			)
			SELECT a.id,
			       coalesce(nullif(a.display_name, ''), nullif(a.hostname, ''), host(a.primary_address), ''),
			       (SELECT value FROM latest WHERE latest.asset_id = a.id AND latest.key = $3),
			       coalesce((SELECT value #>> '{}' FROM latest WHERE latest.asset_id = a.id AND latest.key = $4), ''),
			       coalesce((SELECT source_ref FROM latest WHERE latest.asset_id = a.id AND latest.key = $3), ''),
			       (SELECT observed_at FROM latest WHERE latest.asset_id = a.id AND latest.key = $3),
			       EXISTS (SELECT 1 FROM latest
			               WHERE latest.asset_id = a.id AND latest.key IN ($3, $4)
			                 AND latest.expires_at IS NOT NULL AND latest.expires_at <= now())
			FROM assets a
			WHERE a.tenant_id = $1
			  AND a.deleted_at IS NULL
			  AND a.asset_status <> 'archived'`,
			tenantID,
			textArray(facts.KeyMgmtPlaintext, facts.KeyMgmtProtocol),
			facts.KeyMgmtPlaintext, facts.KeyMgmtProtocol)
		if err != nil {
			return fmt.Errorf("query assets: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var a configAsset
			// The jsonb value arrives as raw text so that MISSING and `false`
			// stay distinguishable. `value #>> '{}'` on an absent row and on a
			// `false` row both scan into "" through a NullString, which is the
			// exact collapse standards/fact-keys.yaml warns about on this key.
			var raw []byte
			var seenAt sql.NullTime
			if err := rows.Scan(&a.id, &a.label, &raw, &a.mgmtProtocol, &a.factSource, &seenAt,
				&a.factExpired); err != nil {
				return fmt.Errorf("scan asset: %w", err)
			}
			a.mgmtPlaintext = parseJSONBool(raw)
			if seenAt.Valid {
				a.factSeenAt = seenAt.Time
			}
			cp := a
			byID[a.id] = &cp
			order = append(order, a.id)
		}
		if err := rows.Err(); err != nil {
			return err
		}

		eRows, err := tx.QueryContext(ctx, `
			SELECT e.id, e.asset_id,
			       coalesce(host(e.address), ''), coalesce(e.fqdn, ''),
			       coalesce(e.port, 0), e.transport,
			       coalesce(e.service_name, ''), coalesce(e.service_version, ''),
			       coalesce(e.service_identification_method, ''),
			       coalesce(e.protocol::text, ''),
			       e.bound_local, e.status
			FROM asset_endpoints e
			JOIN assets a ON a.tenant_id = e.tenant_id AND a.id = e.asset_id
			WHERE e.tenant_id = $1
			  AND e.status <> 'closed'
			  AND a.deleted_at IS NULL
			  AND a.asset_status <> 'archived'`, tenantID)
		if err != nil {
			return fmt.Errorf("query endpoints: %w", err)
		}
		defer func() { _ = eRows.Close() }()
		for eRows.Next() {
			var assetID uuid.UUID
			var ep configEndpoint
			var addr, fqdn string
			if err := eRows.Scan(&ep.id, &assetID, &addr, &fqdn,
				&ep.facts.Port, &ep.facts.Transport,
				&ep.facts.ServiceName, &ep.facts.ServiceVersion,
				&ep.facts.IdentificationMethod, &ep.facts.Protocol,
				&ep.boundLocal, &ep.status); err != nil {
				return fmt.Errorf("scan endpoint: %w", err)
			}
			ep.label = endpointLabel(addr, fqdn, ep.facts.Port, ep.facts.Transport)
			if a, ok := byID[assetID]; ok {
				a.endpoints = append(a.endpoints, ep)
			}
		}
		return eRows.Err()
	})
	if err != nil {
		return nil, err
	}

	out := make([]configAsset, 0, len(order))
	for _, id := range order {
		out = append(out, *byID[id])
	}
	return out, nil
}

// plannedConfig is one finding the plan phase decided on.
type plannedConfig struct {
	finding producer.Finding
}

// plan turns the read inventory into findings. No I/O: the rule table is in
// this package.
//
// It also decides the coverage set. An asset is EXAMINED when there was
// something here to look at — an explicit `mgmt.plaintext` fact of either
// value, or at least one active endpoint the rule table ran over. An asset with
// neither is read and not claimed: see the type comment.
func (p *ConfigurationProducer) plan(subjects []configAsset, run *ConfigRun) ([]plannedConfig, []uuid.UUID, sweepHold) {
	var planned []plannedConfig
	var assessed []uuid.UUID
	withheld := sweepHold{}

	for _, a := range subjects {
		run.Assets++
		if a.factExpired {
			// Stopped knowing, rather than learned there is nothing. The
			// subject is withheld from the sweep so a finding raised while the
			// fact was current stays raised.
			run.FactsExpired++
			withheld[findings.KindPlaintextManagement] = append(
				withheld[findings.KindPlaintextManagement],
				producer.Subject{Type: findings.SubjectAsset, ID: a.id})
		} else if f := p.planFactPlaintext(a, run); f != nil {
			planned = append(planned, *f)
		}
		judged := 0
		for _, ep := range a.endpoints {
			if ep.status != endpointActive {
				// Nothing has observed this socket for the stale ladder's first
				// rung. Not judged, and not swept: see configEndpoint.status.
				run.EndpointsUnobserved++
				for _, kind := range configurationKinds {
					withheld[kind] = append(withheld[kind],
						producer.Subject{Type: findings.SubjectEndpoint, ID: ep.id})
				}
				continue
			}
			judged++
			run.Endpoints++
			planned = append(planned, p.planEndpoint(a, ep, run)...)
		}
		if (a.mgmtPlaintext != nil && !a.factExpired) || judged > 0 {
			assessed = append(assessed, a.id)
		}
	}
	return planned, assessed, withheld
}

// planFactPlaintext raises plaintext_management on the ASSET from the
// interrogation facts.
//
// Three-valued, and the middle value is the point. `mgmt.plaintext` absent is
// NOT ASSESSED and produces nothing; an explicit `false` is an ANSWER and also
// produces nothing, but is counted — so the run can report how much of the
// estate has been looked at. Only an explicit `true` is a finding.
//
// The evidence names the two fact keys and the fact's own source_ref. It never
// carries the community string, the credential or anything else the
// interrogation saw: this producer reads exactly two registered keys, and both
// are `redact: false` posture values by their registry entries.
func (p *ConfigurationProducer) planFactPlaintext(a configAsset, run *ConfigRun) *plannedConfig {
	if a.mgmtPlaintext == nil {
		return nil
	}
	run.PlaintextAssessed++
	if !*a.mgmtPlaintext {
		return nil
	}

	detail := strings.TrimSpace(a.mgmtProtocol)
	if detail == "" {
		// The plaintext fact without the protocol fact beside it. Say that,
		// rather than naming a protocol nobody measured.
		detail = "protocol not recorded"
	}

	evidence := map[string]any{
		"matched_by": signalFact,
		"fact_keys":  []string{facts.KeyMgmtPlaintext, facts.KeyMgmtProtocol},
		"subject":    "asset",
	}
	if a.mgmtProtocol != "" {
		evidence["mgmt_protocol"] = a.mgmtProtocol
	}
	if a.factSource != "" {
		evidence["fact_source_ref"] = a.factSource
	}
	if !a.factSeenAt.IsZero() {
		evidence["fact_observed_at"] = a.factSeenAt.UTC().Format(time.RFC3339)
	}

	f, ok := p.finding(findings.KindPlaintextManagement,
		producer.Subject{Type: findings.SubjectAsset, ID: a.id}, a.label, detail, evidence)
	if !ok {
		return nil
	}
	return &plannedConfig{finding: f}
}

// planEndpoint runs the rule table over one endpoint.
func (p *ConfigurationProducer) planEndpoint(a configAsset, ep configEndpoint, run *ConfigRun) []plannedConfig {
	// A socket bound to loopback is not exposed to anything, and neither kind
	// describes it: the management plane of a device reachable only from itself
	// is not on the network, and a Redis on 127.0.0.1 is the recommended
	// configuration rather than the finding.
	//
	// `bound_local` is three-valued and only TRUE is excluded. NULL means
	// nobody established it — which is every endpoint a network scan found, and
	// a scan that saw the socket answer reached it from somewhere else, so NULL
	// leans toward exposed rather than away from it. The value travels in
	// evidence either way, so a reader can see whether exposure was measured or
	// assumed.
	if ep.boundLocal != nil && *ep.boundLocal {
		return nil
	}

	matches := matchConfigurationRules(ep.facts)
	out := make([]plannedConfig, 0, len(matches))
	for _, m := range matches {
		switch m.Signal {
		case signalServiceName:
			run.MatchedByName++
		case signalPort:
			run.MatchedByPort++
		}

		evidence := map[string]any{
			"rule_id":    m.Rule.ID,
			"matched_by": m.Signal,
			"matched":    m.Matched,
			"service":    m.Rule.Service,
			"why":        m.Rule.Why,
			"port":       ep.facts.Port,
			"transport":  ep.facts.Transport,
			// The host, so the drawer's "where in the network" button and the
			// ticket mapping can reach it: an endpoint has no page of its own.
			"asset_id": a.id.String(),
		}
		if ep.facts.ServiceName != "" {
			evidence["observed_service"] = ep.facts.ServiceName
		}
		if ep.facts.ServiceVersion != "" {
			evidence["observed_service_version"] = ep.facts.ServiceVersion
		}
		if ep.facts.IdentificationMethod != "" {
			evidence["identification_method"] = ep.facts.IdentificationMethod
		}
		if ep.boundLocal == nil {
			// Explicit, because the distinction is the whole three-valued
			// point: "nobody measured whether this is reachable" is not
			// "measured reachable".
			evidence["bound_local"] = nil
		} else {
			evidence["bound_local"] = *ep.boundLocal
		}

		f, ok := p.finding(m.Rule.Kind,
			producer.Subject{Type: findings.SubjectEndpoint, ID: ep.id},
			ep.label, m.Rule.Detail, evidence)
		if !ok {
			continue
		}
		out = append(out, plannedConfig{finding: f})
	}
	return out
}

// finding builds one finding at the registry's severity and score for the kind.
//
// Both come from the registry and neither is computed here: these are `fixed`
// kinds, so `default_severity` and `score` ARE the answer, and a producer that
// picked its own pair would make the YAML a description of a decision taken
// somewhere else. A kind that is somehow not in the registry returns ok=false
// rather than a zero-valued finding — the writer would refuse it anyway, and
// refusing here keeps the refusal next to the reason.
func (p *ConfigurationProducer) finding(kind string, subject producer.Subject, label, detail string, evidence map[string]any) (producer.Finding, bool) {
	k, ok := findings.Get(findings.ProducerConfiguration, kind)
	if !ok {
		return producer.Finding{}, false
	}
	return producer.Finding{
		Kind:         kind,
		Subject:      subject,
		SubjectLabel: label,
		Severity:     k.DefaultSeverity,
		Score:        k.Score,
		Summary:      renderTemplate(k.TitleTemplate, label, detail),
		Evidence:     evidence,
		// measured: every signal behind these findings was observed on the
		// tenant's own network — a socket that answered, a protocol an
		// interrogation used. Nothing here was imported from a catalogue.
		SourceKind: producer.SourceMeasured,
	}, true
}

// write commits the run: every finding, the coverage claim, then the sweep —
// one transaction, because a sweep that lands without its upserts inactivates
// live findings, and a coverage claim that outlives the rollback of the
// findings justifying it reads "assessed, nothing found" forever.
func (p *ConfigurationProducer) write(ctx context.Context, tenantID uuid.UUID, planned []plannedConfig, assessed []uuid.UUID, withheld sweepHold, run *ConfigRun) error {
	seen := map[string][]producer.Subject{}
	for _, kind := range configurationKinds {
		// Seeded with the subjects this pass DECLINED to judge. `seen` is what
		// the sweep spares, and an asset whose interrogation facts have expired
		// is one this producer can say nothing about — see
		// configAsset.factExpired.
		seen[kind] = append([]producer.Subject(nil), withheld[kind]...)
	}

	return p.repo.RunInTx(ctx, tenantID.String(), func(r *pgidentity.Repository) error {
		tx := r.Tx()

		for _, plan := range planned {
			if _, err := p.writer.Upsert(ctx, tx, tenantID, plan.finding); err != nil {
				return err
			}
			run.Raised++
			seen[plan.finding.Kind] = append(seen[plan.finding.Kind], plan.finding.Subject)
		}

		// The coverage claim — ASSET ids, even though two of the three kinds
		// are raised on an endpoint. Coverage is a statement about an asset,
		// which is what the asset page and the compliance `finding` shape ask
		// about; `mgmt_plaintext` counts both subject types under one asset
		// through `via: asset_or_endpoint`.
		n, err := p.writer.MarkAssessed(ctx, tx, tenantID, assessed)
		if err != nil {
			return err
		}
		run.Assessed = n

		// The sweep, per kind. One call per kind covers BOTH subject types:
		// `seen` carries (type, id) pairs and Sweep's NOT EXISTS is over the
		// pair, so an asset-subject plaintext finding and an endpoint-subject
		// one are swept by the same statement without either hiding the other.
		for _, kind := range configurationKinds {
			n, err := p.writer.Sweep(ctx, tx, tenantID, kind, seen[kind])
			if err != nil {
				return err
			}
			run.Resolved += n
		}
		return nil
	})
}

// renderTemplate substitutes a registry title_template's two placeholders.
func renderTemplate(tmpl, subject, detail string) string {
	s := strings.ReplaceAll(tmpl, "{subject}", subject)
	return strings.ReplaceAll(s, "{detail}", detail)
}

// parseJSONBool reads a jsonb scalar as a three-valued boolean.
//
// nil for SQL NULL (no fact) and for anything that is not a JSON boolean; a
// pointer to the value otherwise. The distinction between nil and a pointer to
// false is the entire contract of the `mgmt.plaintext` key — "an explicit false
// is an answer, not an absence" — and reading the column through a scanner that
// collapses them is how that contract would quietly stop holding.
func parseJSONBool(raw []byte) *bool {
	switch strings.TrimSpace(string(raw)) {
	case "true":
		v := true
		return &v
	case "false":
		v := false
		return &v
	default:
		return nil
	}
}

// endpointLabel is what the finding's subject_label carries: the address a
// person would type, with the port and transport.
//
// A FALLBACK for a reader whose join finds nothing, not the display path — but
// an endpoint has no display name of its own anywhere, so in practice this is
// what the Findings page shows.
func endpointLabel(addr, fqdn string, port int, transport string) string {
	host := addr
	if host == "" {
		host = fqdn
	}
	if host == "" {
		host = "endpoint"
	}
	if port <= 0 {
		return host
	}
	t := strings.ToLower(strings.TrimSpace(transport))
	if t == "" || t == "tcp" {
		return host + ":" + strconv.Itoa(port)
	}
	return host + ":" + strconv.Itoa(port) + "/" + t
}
