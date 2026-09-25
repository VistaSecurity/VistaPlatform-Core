package services

// Interrogation findings are owned by the interrogated device ( W2.2,
// findings P-10 and P-11).
//
// A device interrogation reads a device's CONFIGURATION. Every crypto
// configuration it reports — a FortiGate's IPsec tunnel, an F5 virtual
// server's client-ssl profile, a PAN-OS decryption profile, a UniFi gateway's
// WAN VPN — is a statement about that device, whatever address (if any) the
// configuration names. The ingest used to ignore that and route the finding by
// its address alone:
//
//   - a PUBLIC address (a tunnel's remote gateway, a public VIP, the gateway's
//     own WAN) classified third_party, and with no source IP there was no
//     connection row to write either — discovery-processor dropped it with a
//     stdout warning and the job reported success;
//   - NO address (a rule or profile that names none) became the 0.0.0.0
//     placeholder, which is not RFC 1918, so the same thing happened.
//
// Such a finding now lands on the interrogated device: its crypto
// configuration is the device's, with an endpoint of (address, port) when the
// finding had an address and none when it did not. It is never routed to
// external_connections, never made into a new asset, and a label is never
// resolved or turned into an FQDN endpoint.
//
// A finding at one of the DEVICE'S OWN addresses (its primary address, or a
// MEASURED ip_address identifier it already holds) is owned too, whatever
// network the address is in: it is the device's own management plane, and the
// identification engine could not reliably recognise it —
// outside a registered segment an address does not vote, and the engine
// minted a second asset for the device (see isDeviceOwnAddress).
//
// Every other private-address finding keeps today's routing: an F5 private VIP
// still becomes its own asset through the identification engine. That is a
// separate question (a VIP is arguably a service of the device, arguably its
// own thing) and this slice deliberately does not answer it.
//
// # Trust
//
// `source_asset_id` is a field in a metadata blob, and host inventory's
// hostConnectionSourceAssetID already explains why such a field is not
// identity by itself: any producer can write one. It is honoured here only
// when all of these hold, each checked against the database rather than
// against the payload:
//
//   - the finding says it came from device interrogation;
//   - it was written under THIS tenant's platform-managed sensor —
//     sensors.platform_managed, the one marker no tenant path writes. The
//     profile, the `system` tag and `platform = 'platform'` are NOT that
//     marker: all three were settable by a tenant sensor at registration or
//     through PUT /sensors/:id/config (review B1), and are now only reserved;
//   - it names the DEVICE JOB that produced it (device_job_id, stamped by
//     device-interrogation-service from its own record of the run, after
//     anything forwarded), and that job exists in this tenant, is a
//     device_interrogation job, is in progress or completed, and interrogated
//     EXACTLY the claimed asset. The claim is bound to a real interrogation of
//     that asset, not to whatever asset id a row carries;
//   - the asset exists in this tenant and is not deleted.
//
// A claim that fails any of these is REJECTED when the finding would have
// gone to the device — never routed by its address instead. A finding that
// makes no claim takes the ordinary path, unchanged.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// interrogationDiscoveryMethod is the discovery_method device-interrogation-
// service stamps on every interrogated asset it publishes.
const interrogationDiscoveryMethod = "device_interrogation"

// interrogationOwnerClaim reads the claim a finding makes about which
// interrogated device owns it, without trusting it. ok is false when the
// finding makes no such claim.
func interrogationOwnerClaim(f IngestFinding) (owner, sensor uuid.UUID, ok bool) {
	if f.RawData == nil || f.SourceSensorID == nil {
		return uuid.Nil, uuid.Nil, false
	}
	if dm, _ := f.RawData["discovery_method"].(string); dm != interrogationDiscoveryMethod {
		return uuid.Nil, uuid.Nil, false
	}
	raw, _ := f.RawData["source_asset_id"].(string)
	owner, err := uuid.Parse(strings.TrimSpace(raw))
	if err != nil || owner == uuid.Nil {
		return uuid.Nil, uuid.Nil, false
	}
	sensor, err = uuid.Parse(strings.TrimSpace(*f.SourceSensorID))
	if err != nil || sensor == uuid.Nil {
		return uuid.Nil, uuid.Nil, false
	}
	return owner, sensor, true
}

// claimedDeviceJob reads the device job a finding says produced it.
func claimedDeviceJob(f IngestFinding) (uuid.UUID, bool) {
	raw, _ := f.RawData["device_job_id"].(string)
	id, err := uuid.Parse(strings.TrimSpace(raw))
	if err != nil || id == uuid.Nil {
		return uuid.Nil, false
	}
	return id, true
}

// interrogationOwner returns the interrogated device that owns a finding, when
// the finding claims one AND the claim checks out (see the file comment).
//
// claimed reports whether the finding made the claim at all. A claim that does
// not check out is logged and reported as claimed-but-not-owned; the caller
// REJECTS such a finding rather than routing it by address, because the only
// route left for an address-less or public interrogation finding is
// external_connections — and a tunnel's far end, a public VIP or a rule label
// is not a connection the tenant made (the external path would even resolve a
// hostname-only row through DNS).
func (s *AssetService) interrogationOwner(ctx context.Context, tenantID uuid.UUID, f IngestFinding) (uuid.UUID, bool, bool, error) {
	owner, sensor, claimed := interrogationOwnerClaim(f)
	if !claimed || s.db == nil {
		return uuid.Nil, false, claimed, nil
	}
	deviceJob, jobOK := claimedDeviceJob(f)
	if !jobOK {
		log.Printf("[AssetService] IngestFindings: %s claims interrogated device %s but names no device job; the claim is refused",
			findingLabel(f), owner)
		return uuid.Nil, false, true, nil
	}
	var platformSensor, jobBound, assetLive bool
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM sensors
				 WHERE tenant_id = $1 AND id = $2
				   AND platform_managed
				   AND deleted_at IS NULL)`, tenantID, sensor).Scan(&platformSensor); err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM device_jobs
				 WHERE id = $1 AND tenant_id = $2 AND asset_id = $3
				   AND job_type = 'device_interrogation'
				   AND status IN ('in_progress', 'completed'))`, deviceJob, tenantID, owner).Scan(&jobBound); err != nil {
			return err
		}
		return tx.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM assets
				 WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL)`, tenantID, owner).Scan(&assetLive)
	})
	if err != nil {
		return uuid.Nil, false, true, fmt.Errorf("verify interrogation owner: %w", err)
	}
	switch {
	case !platformSensor:
		log.Printf("[AssetService] IngestFindings: %s claims interrogated device %s but was not written by this tenant's platform-managed sensor; the claim is refused",
			findingLabel(f), owner)
		return uuid.Nil, false, true, nil
	case !jobBound:
		log.Printf("[AssetService] IngestFindings: %s claims interrogated device %s, but device job %s is not a running or completed interrogation of that asset in this tenant; the claim is refused",
			findingLabel(f), owner, deviceJob)
		return uuid.Nil, false, true, nil
	case !assetLive:
		log.Printf("[AssetService] IngestFindings: %s names interrogated device %s, which does not exist in this tenant (deleted since the run?); the claim is refused",
			findingLabel(f), owner)
		return uuid.Nil, false, true, nil
	}
	return owner, true, true, nil
}

// ownedByInterrogatedDevice decides whether an interrogation finding goes to
// its device rather than through ordinary routing: it has no address, or the
// address classifies third_party. A private or registered address keeps the
// ordinary path.
func ownedByInterrogatedDevice(effectiveIP *string, ownership string) bool {
	return effectiveIP == nil || ownership == "third_party"
}

// isDeviceOwnAddress reports whether ip is one of the interrogated device's
// OWN addresses: its primary address, an ip_address identifier already on the
// asset that was MEASURED — never a declared one.
//
// The management URL is deliberately not a source (review of): it is
// what an operator TYPED into the device form, and ADR-0002 D4 keeps declared
// and measured apart. A declared address can be wrong, or someone else's, and
// letting it pull findings onto the device would let a typo decide ownership.
//
// A finding at such an address — Cisco's SSH management service, a UniFi
// controller's own HTTPS — describes the device itself. Handed to the
// identification engine it could only match the device through an ip_address
// identifier, and an address outside every registered segment is unscoped and
// does not vote (ADR-0002 D3): the engine then minted a SECOND asset for the
// device's own management plane. So it is owned, exactly like a public or
// address-less finding, and never reaches the engine.
//
// Only asked about a finding whose ownership claim has already verified.
func (s *AssetService) isDeviceOwnAddress(ctx context.Context, tenantID, device uuid.UUID, ip string) (bool, error) {
	want := net.ParseIP(strings.TrimSpace(ip))
	if want == nil || want.IsUnspecified() {
		return false, nil
	}
	var addresses []string
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT host(primary_address) FROM assets
			 WHERE tenant_id = $1 AND id = $2 AND primary_address IS NOT NULL
			UNION ALL
			SELECT value FROM asset_identifiers
			 WHERE tenant_id = $1 AND asset_id = $2 AND kind = 'ip_address'
			   AND source_kind = 'measured'`, tenantID, device)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var v string
			if err := rows.Scan(&v); err != nil {
				return err
			}
			addresses = append(addresses, v)
		}
		return rows.Err()
	})
	if err != nil {
		return false, fmt.Errorf("read the interrogated device's own addresses: %w", err)
	}
	for _, a := range addresses {
		if have := addressOf(a); have != nil && have.Equal(want) {
			return true, nil
		}
	}
	return false, nil
}

// addressOf reads an IP from a stored address or identifier value. Nothing is
// resolved.
func addressOf(v string) net.IP {
	return net.ParseIP(strings.TrimSpace(v))
}

// deviceOwnedFinding is the finding as it is materialised on the device:
//
//   - the address is the endpoint the configuration answers on, or none;
//   - the hostname is dropped. For an address-less finding it is a collector
//     label (a rule name), and findingEndpoint would make a dotted label into
//     an FQDN endpoint of the device. The label is kept in raw_data as
//     config_name, which is what it is.
func deviceOwnedFinding(f IngestFinding, effectiveIP *string) IngestFinding {
	out := f
	out.Hostname = nil
	out.IPAddress = effectiveIP
	return out
}

// attachToInterrogatedDevice materialises an owned finding on its device and
// reports the status the device has, exactly as the resolved path reports the
// status of the asset a finding landed on.
func (s *AssetService) attachToInterrogatedDevice(
	ctx context.Context,
	tenantID, owner uuid.UUID,
	f IngestFinding,
	onMaterialize func(assetID uuid.UUID, owned IngestFinding) error,
) (uuid.UUID, string, bool, error) {
	owned := deviceOwnedFinding(f, nonPlaceholderIP(f.IPAddress))
	var landed uuid.UUID
	var landedStatus string
	retired := false
	err := s.withResolvedAssetLifecycle(ctx, tenantID, owner, func(current uuid.UUID, status string, deleted bool) error {
		landed, landedStatus = current, status
		if deleted || status == identity.StatusArchived || status == "denied" {
			// The tenant retired the device. Its configuration is neither
			// materialised nor deferred — the same answer the resolved path
			// gives an archived or denied asset.
			// Reported as retired, so the caller rejects the finding with a
			// reason instead of claiming a match that landed nothing.
			retired = true
			return nil
		}
		if status != identity.StatusMonitoring {
			s.storeDeferredFinding(tenantID, current, owned)
			return nil
		}
		return onMaterialize(current, owned)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, "", false, fmt.Errorf("interrogated device %s vanished before its finding landed: %w", owner, err)
	}
	return landed, landedStatus, retired, err
}

// nonPlaceholderIP is the finding's address with the unspecified placeholder
// (and an empty string) read as absent.
func nonPlaceholderIP(ip *string) *string {
	if ip == nil || strings.TrimSpace(*ip) == "" || isUnspecifiedIP(*ip) {
		return nil
	}
	return ip
}
