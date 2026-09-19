package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

var ErrIdentityDNSUnavailable = errors.New("observing sensor lacks current scoped DNS capability or network reachability")
var ErrIdentityDNSReplay = errors.New("DNS request identifier was reused with different contents")

// EnqueueIdentityDNS uses the existing authenticated sensor command path. The
// caller must apply tenant enrichment policy and exclusions before calling.
// This function independently enforces ownership, capability and segment reachability.
func EnqueueIdentityDNS(ctx context.Context, tx *sql.Tx, tenant, sensor uuid.UUID, req sensordispatch.IdentityDNSRequest) (uuid.UUID, error) {
	if err := req.Validate(); err != nil {
		return uuid.Nil, err
	}
	id := uuid.NewSHA1(tenant, []byte("identity-dns:"+sensor.String()+":"+req.RequestID))
	payload, err := json.Marshal(req)
	if err != nil {
		return uuid.Nil, err
	}
	var same bool
	err = tx.QueryRowContext(ctx, `SELECT c.sensor_id=$3 AND c.command_type=$4 AND c.payload=$5::jsonb
 FROM sensor_commands c JOIN sensors s ON s.id=c.sensor_id WHERE s.tenant_id=$1 AND c.id=$2`, tenant, id, sensor, sensordispatch.IdentityDNSCommand, payload).Scan(&same)
	if err == nil {
		if !same {
			return uuid.Nil, ErrIdentityDNSReplay
		}
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, err
	}
	var allowed bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM sensors s JOIN network_segments n ON n.tenant_id=s.tenant_id
 WHERE s.tenant_id=$1 AND s.id=$2 AND s.deleted_at IS NULL AND s.status='active' AND NOT s.air_gapped
 AND s.last_heartbeat>now()-interval '2 minutes' AND $3=ANY(s.reported_capabilities)
 AND n.id=$4 AND n.is_active AND CASE WHEN n.segment_type='cidr' THEN n.value::cidr=$5::cidr ELSE false END
 AND EXISTS(SELECT 1 FROM agent_addresses a WHERE a.sensor_id=s.id AND a.address <<=$5::cidr
 AND a.interface_name=ANY(s.reported_dns_interfaces) AND a.last_seen_at>now()-interval '5 minutes')
 AND EXISTS(SELECT 1 FROM identity_observations o WHERE o.tenant_id=$1 AND o.id=$6))`, tenant, sensor, sensordispatch.IdentityDNSCapability, req.NetworkScope, req.SegmentCIDR, req.ObservationID).Scan(&allowed)
	if err != nil {
		return uuid.Nil, err
	}
	if !allowed {
		return uuid.Nil, ErrIdentityDNSUnavailable
	}
	// INSERT conflict + equality read also covers concurrent attempts without taking
	// an observation row lock that would invert the identity ingestion lock order.
	_, err = tx.ExecContext(ctx, `INSERT INTO sensor_commands(id,sensor_id,command_type,payload,expires_at) VALUES($1,$2,$3,$4::jsonb,now()+interval '5 minutes') ON CONFLICT(id) DO NOTHING`, id, sensor, sensordispatch.IdentityDNSCommand, payload)
	if err != nil {
		return uuid.Nil, err
	}
	if err = tx.QueryRowContext(ctx, `SELECT sensor_id=$2 AND command_type=$3 AND payload=$4::jsonb FROM sensor_commands WHERE id=$1`, id, sensor, sensordispatch.IdentityDNSCommand, payload).Scan(&same); err != nil {
		return uuid.Nil, err
	}
	if !same {
		return uuid.Nil, ErrIdentityDNSReplay
	}
	return id, nil
}

// PollIdentityDNS returns a terminal result only from the selected tenant sensor.
func PollIdentityDNS(ctx context.Context, tx *sql.Tx, tenant, sensor, command uuid.UUID) (string, *sensordispatch.IdentityDNSResult, error) {
	var status string
	var expired bool
	var created time.Time
	var payload, data []byte
	err := tx.QueryRowContext(ctx, `SELECT c.status,c.expires_at<now(),c.created_at,c.payload,c.response_data FROM sensor_commands c JOIN sensors s ON s.id=c.sensor_id
 WHERE s.tenant_id=$1 AND c.sensor_id=$2 AND c.id=$3 AND c.command_type=$4`, tenant, sensor, command, sensordispatch.IdentityDNSCommand).Scan(&status, &expired, &created, &payload, &data)
	if err != nil {
		return "", nil, err
	}
	if status != "completed" && status != "failed" {
		if expired {
			return "expired", nil, nil
		}
		return status, nil, nil
	}
	if len(data) == 0 {
		return status, nil, nil
	}
	var req sensordispatch.IdentityDNSRequest
	var result sensordispatch.IdentityDNSResult
	if err = json.Unmarshal(payload, &req); err != nil {
		return "", nil, err
	}
	if err = json.Unmarshal(data, &result); err != nil {
		return "", nil, err
	}
	if req.RequestID != result.RequestID || req.ObservationID != result.ObservationID || req.Hostname != result.Hostname || req.NetworkScope != result.NetworkScope {
		return "", nil, fmt.Errorf("DNS response does not match the queued request")
	}

	if status == "completed" && result.ErrorCode == "" {
		if result.ObservedAt.IsZero() || result.ObservedAt.Before(created.Add(-2*time.Minute)) || result.ObservedAt.After(time.Now().Add(2*time.Minute)) || len(result.Addresses) > req.MaxAddresses {
			return "", nil, fmt.Errorf("DNS response exceeds requested bounds")
		}
		prefix, err := netip.ParsePrefix(req.SegmentCIDR)
		if err != nil {
			return "", nil, err
		}
		for _, value := range result.Addresses {
			address, err := netip.ParseAddr(value)
			if err != nil || !prefix.Contains(address.Unmap()) || address.IsUnspecified() || address.IsMulticast() || address.IsLoopback() {
				return "", nil, fmt.Errorf("DNS response address outside requested scope")
			}
		}
	}
	return status, &result, nil
}
