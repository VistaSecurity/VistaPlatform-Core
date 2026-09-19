package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/identityenrichment"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgrepo "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

// corroborateDNS links an unresolved name only when THIS authorized probe
// produced retained direct evidence for THIS scoped DNS response. DNS itself
// never gains Direct or Authoritative provenance. Multiple-address/service
// answers and DHCP addresses without actual interface proof remain unresolved.
func (b *IdentityEnrichmentBackend) corroborateDNS(ctx context.Context, tenant uuid.UUID, o identityenrichment.Observation, dnsJob identityenrichment.Job) error {
	var dns sensordispatch.IdentityDNSResult
	if err := json.Unmarshal(dnsJob.Result, &dns); err != nil {
		return err
	}
	if len(dns.Addresses) != 1 {
		return nil
	}
	for _, id := range o.Evidence.Identifiers {
		if (id.Kind != identity.KindHostname && id.Kind != identity.KindFQDN) || canonicalEnrichmentAlias(id.Value) != canonicalEnrichmentAlias(dns.Hostname) {
			return nil
		}
	}
	var proof identity.Observation
	var expectedAsset string
	var probeJob uuid.UUID
	err := database.WithTenantTx(ctx, b.assets.db, tenant, func(tx *sqlx.Tx) error {
		var raw []byte
		err := tx.QueryRowContext(ctx, `SELECT r.evidence,po.asset_id::text,j.id
   FROM identity_enrichment_jobs j
   JOIN discovery_jobs d ON d.tenant_id=j.tenant_id AND d.id::text=j.remote_id
   JOIN sensor_discoveries sd ON sd.tenant_id=j.tenant_id AND sd.sensor_id=$3
    AND (sd.metadata->'raw_metadata'->>'job_id'=j.remote_id OR sd.metadata->>'job_id'=j.remote_id)
   JOIN identity_observation_receipts r ON r.tenant_id=sd.tenant_id AND r.evidence->'admission'->>'receipt_id'=sd.id::text
   JOIN identity_observations po ON po.tenant_id=r.tenant_id AND po.id=r.observation_id
   WHERE j.tenant_id=$1 AND j.observation_id=$2 AND j.action='probe' AND j.state='completed' AND d.status='completed'
    AND sd.processed_at IS NOT NULL AND sd.dest_ip=$4::inet AND po.asset_id IS NOT NULL AND po.state='linked'
    AND r.evidence->'network'->>'segment_id'=$5 AND r.evidence->'admission'->>'direct'='true'
    AND COALESCE(r.evidence->'admission'->>'relayed','false')='false'
    AND r.observed_at BETWEEN $6::timestamptz-interval '2 minutes' AND $6::timestamptz+interval '15 minutes'
   ORDER BY r.observed_at DESC LIMIT 1`, tenant, o.ID, dnsJob.Plan.SensorID, dns.Addresses[0], dns.NetworkScope, dns.ObservedAt).Scan(&raw, &expectedAsset, &probeJob)
		if err != nil {
			return err
		}
		return json.Unmarshal(raw, &proof)
	})
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	if proof.TenantID != tenant.String() || !proof.Admission.Direct || proof.Admission.Relayed {
		return fmt.Errorf("invalid retained probe proof")
	}
	// Use the actual probe's clock, interface proof, class and endpoints. Add only
	// the name resolved by the separately authenticated scoped DNS measurement.
	proof.Identifiers = append(proof.Identifiers, o.Evidence.Identifiers...)
	proof.Source = identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:identity-corroboration:" + dnsJob.Plan.SensorID.String(), Mode: identity.ModeActive}
	proof.Admission.ReceiptID = uuid.NewSHA1(probeJob, []byte(dnsJob.RequestID.String()+":"+proof.Admission.ReceiptID)).String()
	proof.Hostname = dns.Hostname
	engine, err := b.assets.identityEngine()
	if err != nil {
		return err
	}
	return b.assets.identityRepo.RunInTx(ctx, tenant.String(), func(repo *pgrepo.Repository) error {
		active, err := enrichmentActiveTx(ctx, repo.Tx(), tenant)
		if err != nil {
			return err
		}
		if !active {
			return nil
		}
		dynamicScopes := make(map[string]bool, len(proof.DynamicScopes))
		for scope, value := range proof.DynamicScopes {
			dynamicScopes[scope] = value
		}
		for _, id := range proof.Identifiers {
			if id.Kind == identity.KindIPAddress {
				address, err := netip.ParseAddr(id.Value)
				if err != nil {
					return err
				}
				scope, dynamic, err := repo.ScopeForAddress(ctx, tenant.String(), address, "")
				if err != nil {
					return err
				}
				if scope != dns.NetworkScope {
					return nil
				}
				dynamicScopes[scope] = dynamicScopes[scope] || dynamic
			}
		}
		proof.DynamicScopes = dynamicScopes
		if err := repo.LockIdentifiers(ctx, tenant.String(), proof.Identifiers); err != nil {
			return err
		}
		var state string
		var currentRaw []byte
		if err := repo.Tx().QueryRowContext(ctx, `SELECT state,evidence FROM identity_observations WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, o.ID).Scan(&state, &currentRaw); err != nil {
			return err
		}
		if state != "unresolved" {
			return nil
		}
		var current identity.Observation
		if err := json.Unmarshal(currentRaw, &current); err != nil {
			return err
		}
		original := o
		original.Cycle = ""
		if identityenrichment.Generation(original) != identityenrichment.Generation(identityenrichment.Observation{Evidence: current}) {
			return nil
		}
		resolved, err := engine.WithAutoAcceptThreshold(0).WithRepository(repo).Resolve(ctx, proof)
		if err != nil {
			return err
		}
		if resolved.Outcome == identity.OutcomeConflict || resolved.Asset.Zero() {
			return nil
		}
		if resolved.Asset.ID != expectedAsset {
			return fmt.Errorf("corroborated probe ownership changed")
		}
		if err := repo.LinkObservation(ctx, tenant.String(), o.ID.String(), resolved.Asset.ID, identity.IdentityEstablished); err != nil {
			return err
		}
		_, err = repo.Tx().ExecContext(ctx, `INSERT INTO asset_history(tenant_id,asset_id,source,action,changes_json)
   VALUES($1,$2,'identity_enrichment','updated',jsonb_build_object('kind','observation_corroborated','observation_id',$3::text,'dns_job_id',$4::text,'probe_job_id',$5::text,'proof_observed_at',$6::timestamptz))`, tenant, resolved.Asset.ID, o.ID, dnsJob.ID, probeJob, proof.ObservedAt)
		return err
	})
}

func canonicalEnrichmentAlias(value string) string {
	return strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), "."), ".local")
}
