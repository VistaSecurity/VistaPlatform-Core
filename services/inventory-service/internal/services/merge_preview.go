package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	identitypg "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/redact"
)

var (
	ErrMergeSelection       = errors.New("select one to twenty distinct source assets and a different survivor")
	ErrMergePreviewChanged  = errors.New("merge preview changed; refresh before merging")
	ErrMergeFieldResolution = errors.New("resolve the conflicting declared fields before merging")
	ErrMergeKeptSeparate    = errors.New("a selected pair has a Keep Separate decision")
)

// MergeSelection always names the sources explicitly, including candidate-only proposals.
type MergeSelection struct {
	SourceAssetIDs   []uuid.UUID          `json:"source_asset_ids"`
	SurvivorAssetID  uuid.UUID            `json:"survivor_asset_id"`
	FieldResolutions map[string]uuid.UUID `json:"field_resolutions,omitempty"`
}
type MergeExecutionRequest struct {
	MergeSelection
	Revision string `json:"revision"`
	Reason   string `json:"reason"`
}
type MergePreviewAsset struct {
	AssetID        uuid.UUID      `json:"asset_id"`
	DisplayName    string         `json:"display_name"`
	Hostname       string         `json:"hostname"`
	ClassKey       string         `json:"class_key"`
	AssetStatus    string         `json:"asset_status"`
	IdentityStatus string         `json:"identity_status"`
	Fields         map[string]any `json:"fields"`
}
type MergeFieldValue struct {
	AssetID  uuid.UUID `json:"asset_id"`
	Value    any       `json:"value"`
	Declared bool      `json:"declared"`
}
type MergeFieldConflict struct {
	Field              string            `json:"field"`
	Values             []MergeFieldValue `json:"values"`
	RequiresResolution bool              `json:"requires_resolution"`
}
type MergeChildCount struct {
	Table string `json:"table"`
	Count int    `json:"count"`
}
type AssetMergePreview struct {
	selectedRaw map[string]any
	MergeSelection
	Revision       string               `json:"revision"`
	Assets         []MergePreviewAsset  `json:"assets"`
	Conflicts      []MergeFieldConflict `json:"conflicts"`
	SelectedFields map[string]any       `json:"selected_fields"`
	Children       []MergeChildCount    `json:"children"`
	Evidence       []json.RawMessage    `json:"evidence"`
}
type AssetMergeResult struct {
	ID              uuid.UUID   `json:"id"`
	SurvivorAssetID uuid.UUID   `json:"survivor_asset_id"`
	SourceAssetIDs  []uuid.UUID `json:"source_asset_ids"`
	MergedAt        time.Time   `json:"merged_at"`
	Replayed        bool        `json:"replayed"`
}

var mergeEditableFields = []string{"display_name", "hostname", "class_key", "primary_address", "environment", "business_unit", "owner_email", "support_group", "description", "site", "region", "zone", "location_id", "network_segment_id", "attributes", "tags"}
var mergeSnapshotFields = append(append([]string{}, mergeEditableFields...), "id", "class_path", "class_source_kind", "class_source_ref", "class_confidence", "asset_status", "identity_status", "first_discovered_at", "last_seen_at")

type mergeRecord struct {
	Key    string          `json:"key"`
	Digest string          `json:"digest"`
	Data   json.RawMessage `json:"-"`
}
type mergeSnapshot struct {
	EnrichmentPolicy mergeEnrichmentPolicy
	Assets           []map[string]any
	Records          map[string][]mergeRecord
	Proposals        []json.RawMessage
}

func normalizeMergeSelection(in MergeSelection) (MergeSelection, []uuid.UUID, error) {
	if in.SurvivorAssetID == uuid.Nil || len(in.SourceAssetIDs) < 1 || len(in.SourceAssetIDs) > 20 {
		return in, nil, ErrMergeSelection
	}
	in.SourceAssetIDs = append([]uuid.UUID{}, in.SourceAssetIDs...)
	sort.Slice(in.SourceAssetIDs, func(i, j int) bool { return in.SourceAssetIDs[i].String() < in.SourceAssetIDs[j].String() })
	seen := map[uuid.UUID]bool{in.SurvivorAssetID: true}
	for _, id := range in.SourceAssetIDs {
		if id == uuid.Nil || seen[id] {
			return in, nil, ErrMergeSelection
		}
		seen[id] = true
	}
	for field, id := range in.FieldResolutions {
		valid := field == "management_profile"
		for _, f := range mergeEditableFields {
			if field == f {
				valid = true
			}
		}
		if !valid || !seen[id] {
			return in, nil, ErrMergeSelection
		}
	}
	ids := append(append([]uuid.UUID{}, in.SourceAssetIDs...), in.SurvivorAssetID)
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
	return in, ids, nil
}

// PreviewMerge takes the same locks as execution, so its revision represents a
// coherent current set of candidates, identifiers, children and proposal evidence.
func (s *MergeProposalService) PreviewMerge(ctx context.Context, tenant, proposal uuid.UUID, in MergeSelection) (*AssetMergePreview, error) {
	in, ids, err := normalizeMergeSelection(in)
	if err != nil {
		return nil, err
	}
	var out *AssetMergePreview
	err = identitypg.WithAssetLifecycleWriteLocks(ctx, s.db.DB.DB, tenant, ids, func() error {
		return database.WithTenantTx(ctx, s.db, tenant, func(tx *sqlx.Tx) error {
			if err := lockMergeEnrichmentPolicy(ctx, tx, tenant, false); err != nil {
				return err
			}
			if err := lockMergeSelection(ctx, tx, tenant, ids); err != nil {
				return err
			}
			snap, err := readMergeSnapshot(ctx, tx, tenant, ids)
			if err != nil {
				return err
			}
			out, err = buildMergePreview(in, proposal, snap)
			return err
		})
	})
	return out, err
}

func lockMergeSelection(ctx context.Context, tx *sqlx.Tx, tenant uuid.UUID, ids []uuid.UUID) error {
	before, err := mergeIdentifierKeys(ctx, tx, tenant, ids)
	if err != nil {
		return err
	}
	if err := identitypg.LockIdentifierOwnership(ctx, tx.Tx, tenant.String(), before); err != nil {
		return err
	}
	if err := identitypg.LockAssetLifecycleRows(ctx, tx.Tx, tenant, ids); err != nil {
		return err
	}
	// A concurrent admission may have extended the registry while we waited.
	// Never acquire a newly discovered key out of order; ask for a fresh preview.
	after, err := mergeIdentifierKeys(ctx, tx, tenant, ids)
	if err != nil {
		return err
	}
	a, _ := json.Marshal(before)
	b, _ := json.Marshal(after)
	if string(a) != string(b) {
		return ErrMergePreviewChanged
	}
	return nil
}
func mergeIdentifierKeys(ctx context.Context, tx *sqlx.Tx, tenant uuid.UUID, ids []uuid.UUID) ([]identity.Identifier, error) {
	rows, err := tx.QueryContext(ctx, `SELECT kind,value,coalesce(scope,'') FROM asset_identifiers WHERE tenant_id=$1 AND asset_id=ANY($2)
 UNION SELECT i->>'kind',i->>'value',coalesce(i->>'scope','') FROM identity_observations o CROSS JOIN LATERAL jsonb_array_elements(coalesce(o.evidence->'identifiers','[]')) i WHERE o.tenant_id=$1 AND o.asset_id=ANY($2) ORDER BY 1,2,3`, tenant, pq.Array(ids))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []identity.Identifier{}
	for rows.Next() {
		var kind, value, scope string
		if err := rows.Scan(&kind, &value, &scope); err != nil {
			return nil, err
		}
		out = append(out, identity.Identifier{Kind: identity.Kind(kind), Value: value, Scope: scope})
	}
	return out, rows.Err()
}

// All row content contributes to the revision, but only safe fields and record
// identifiers are returned. Passwords, payloads and arbitrary metadata never
// enter the public preview or history.
func readMergeSnapshot(ctx context.Context, tx *sqlx.Tx, tenant uuid.UUID, ids []uuid.UUID) (mergeSnapshot, error) {
	snap := mergeSnapshot{Records: map[string][]mergeRecord{}}
	var err error
	snap.EnrichmentPolicy, err = readMergeEnrichmentPolicy(ctx, tx, tenant, ids)
	if err != nil {
		return snap, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT to_jsonb(a)||jsonb_build_object('_legacy_name_declared',EXISTS(SELECT 1 FROM asset_history h WHERE h.tenant_id=a.tenant_id AND h.asset_id=a.id AND (h.source='manual' OR h.changes_json->>'source_kind'='declared') AND (h.action='created' OR h.changes_json->>'hostname' IS NOT NULL OR h.changes_json->>'display_name' IS NOT NULL))) FROM assets a WHERE tenant_id=$1 AND id=ANY($2) ORDER BY id`, tenant, pq.Array(ids))
	if err != nil {
		return snap, err
	}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			_ = rows.Close()
			return snap, err
		}
		var a map[string]any
		if err := json.Unmarshal(raw, &a); err != nil {
			_ = rows.Close()
			return snap, err
		}
		if a["deleted_at"] != nil || a["asset_status"] == "archived" || a["asset_status"] == "denied" {
			_ = rows.Close()
			return snap, ErrMergePreviewChanged
		}
		snap.Assets = append(snap.Assets, a)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return snap, err
	}
	if len(snap.Assets) != len(ids) {
		return snap, ErrMergeProposalNotFound
	}
	specs := map[string]string{
		"asset_merge_management_history": "asset_id=ANY($2)",
		"assets":                         "id=ANY($2)", "asset_endpoints": "asset_id=ANY($2)", "asset_identifiers": "asset_id=ANY($2)", "asset_management": "asset_id=ANY($2)", "asset_credentials": "asset_id=ANY($2)", "asset_facts": "asset_id=ANY($2)", "asset_history": "asset_id=ANY($2)", "software_installs": "asset_id=ANY($2)", "producer_assessments": "asset_id=ANY($2)", "asset_relationships": "from_asset_id=ANY($2) OR to_asset_id=ANY($2)", "crypto_implementations": "asset_id=ANY($2)", "sensors": "asset_id=ANY($2)",
		"findings":                           "(subject_type='asset' AND subject_id=ANY($2)) OR (subject_type='endpoint' AND subject_id IN (SELECT id FROM asset_endpoints WHERE tenant_id=$1 AND asset_id=ANY($2)))",
		"crypto_implementation_certificates": "crypto_implementation_id IN (SELECT id FROM crypto_implementations WHERE tenant_id=$1 AND asset_id=ANY($2))",
		"implementation_libraries":           "implementation_id IN (SELECT id FROM crypto_implementations WHERE tenant_id=$1 AND asset_id=ANY($2))",
		"crypto_implementation_algorithms":   "crypto_implementation_id IN (SELECT id FROM crypto_implementations WHERE tenant_id=$1 AND asset_id=ANY($2))",
		"implementation_keys":                "implementation_id IN (SELECT id FROM crypto_implementations WHERE tenant_id=$1 AND asset_id=ANY($2))",
	}
	for _, ref := range assetReferrers {
		specs[ref.table] = ref.column + "=ANY($2)"
	}
	for _, ref := range mergeInformalReferrers {
		predicate := ref.column + "=ANY($2)"
		if existing, ok := specs[ref.table]; ok {
			specs[ref.table] = existing + " OR " + predicate
		} else {
			specs[ref.table] = predicate
		}
	}
	for _, table := range []string{"identity_observation_payloads", "identity_observation_receipts", "identity_observation_management", "identity_observation_host_inventories", "identity_observation_peer_contexts", "identity_observation_cloud_contexts", "identity_enrichment_jobs", "identity_source_refreshes"} {
		specs[table] = "observation_id IN (SELECT id FROM identity_observations WHERE tenant_id=$1 AND asset_id=ANY($2))"
	}
	specs["identity_observation_peer_contexts"] += " OR origin_asset_id=ANY($2)"
	for table, predicate := range specs {
		scope := "tenant_id=$1 AND "
		if table == "implementation_keys" || table == "implementation_libraries" || table == "crypto_implementation_algorithms" || table == "crypto_implementation_certificates" {
			scope = ""
		}
		rows, err := tx.QueryContext(ctx, `SELECT to_jsonb(r) FROM `+table+` r WHERE `+scope+`(`+predicate+`) ORDER BY to_jsonb(r)::text`, tenant, pq.Array(ids))
		if err != nil {
			return snap, fmt.Errorf("snapshot merge %s: %w", table, err)
		}
		records := []mergeRecord{}
		for rows.Next() {
			var raw []byte
			if err := rows.Scan(&raw); err != nil {
				_ = rows.Close()
				return snap, err
			}
			var v map[string]any
			if err := json.Unmarshal(raw, &v); err != nil {
				_ = rows.Close()
				return snap, err
			}
			key, ok := v["id"].(string)
			if !ok {
				key, err = mergeCompositeRecordKey(table, v)
				if err != nil {
					_ = rows.Close()
					return snap, err
				}
			}
			sum := sha256.Sum256(raw)
			records = append(records, mergeRecord{Key: key, Digest: hex.EncodeToString(sum[:]), Data: raw})
		}
		err = rows.Err()
		_ = rows.Close()
		if err != nil {
			return snap, err
		}
		snap.Records[table] = records
	}
	rows, err = tx.QueryContext(ctx, `SELECT to_jsonb(h) FROM asset_history h WHERE tenant_id=$1 AND action='merge_proposed' AND changes_json->>'kind'='merge_proposal' AND (asset_id=ANY($2) OR changes_json->>'observation_asset_id'=ANY($3) OR EXISTS(SELECT 1 FROM jsonb_array_elements(coalesce(changes_json->'candidates','[]')) c WHERE c->>'asset_id'=ANY($3))) ORDER BY id FOR UPDATE`, tenant, pq.Array(ids), pq.Array(uuidStrings(ids)))
	if err != nil {
		return snap, err
	}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			_ = rows.Close()
			return snap, err
		}
		snap.Proposals = append(snap.Proposals, json.RawMessage(raw))
	}
	err = rows.Err()
	_ = rows.Close()
	return snap, err
}
func mergeCompositeRecordKey(table string, v map[string]any) (string, error) {
	fieldsByTable := map[string][]string{
		"identity_observation_peer_contexts": {"tenant_id", "context_id"}, "identity_observation_cloud_contexts": {"tenant_id", "observation_id", "receipt_key"},
		"asset_management": {"tenant_id", "asset_id"}, "asset_credentials": {"tenant_id", "asset_id"}, "producer_assessments": {"tenant_id", "asset_id", "producer"},
		"implementation_keys": {"implementation_id", "key_id"}, "implementation_libraries": {"implementation_id", "library_id"},
		"identity_observation_payloads": {"tenant_id", "observation_id", "receipt_key"}, "identity_observation_receipts": {"tenant_id", "observation_id", "receipt_key"}, "identity_observation_management": {"tenant_id", "observation_id"}, "identity_observation_host_inventories": {"tenant_id", "observation_id", "receipt_key"},
	}
	fields, ok := fieldsByTable[table]
	if !ok {
		return "", fmt.Errorf("merge snapshot has no registered record key for %s", table)
	}
	key := map[string]any{}
	for _, field := range fields {
		value, ok := v[field]
		if !ok {
			return "", fmt.Errorf("merge snapshot %s missing key %s", table, field)
		}
		key[field] = value
	}
	b, _ := json.Marshal(key)
	return string(b), nil
}

func buildMergePreview(in MergeSelection, proposal uuid.UUID, snap mergeSnapshot) (*AssetMergePreview, error) {
	selected := map[string]bool{}
	for _, a := range snap.Assets {
		selected[a["id"].(string)] = true
	}
	foundProposal := proposal == uuid.Nil
	evidence := []json.RawMessage{}
	for _, raw := range snap.Proposals {
		var row struct {
			ID         uuid.UUID      `json:"id"`
			Source     string         `json:"source"`
			ProposedAt string         `json:"created_at"`
			Changes    map[string]any `json:"changes_json"`
		}
		if err := json.Unmarshal(raw, &row); err != nil {
			return nil, err
		}
		participants := map[string]bool{}
		if id, ok := row.Changes["observation_asset_id"].(string); ok {
			participants[id] = true
		}
		if cs, ok := row.Changes["candidates"].([]any); ok {
			for _, c := range cs {
				if v, ok := c.(map[string]any); ok {
					if id, ok := v["asset_id"].(string); ok {
						participants[id] = true
					}
				}
			}
		}
		overlap := 0
		for id := range participants {
			if selected[id] {
				overlap++
			}
		}
		if overlap > 1 && row.Changes["status"] == mergeStatusKeptSeparate {
			return nil, ErrMergeKeptSeparate
		}
		if row.ID == proposal {
			foundProposal = true
			if row.Changes["status"] != mergeStatusPending {
				return nil, ErrMergePreviewChanged
			}
			for id := range selected {
				if !participants[id] {
					return nil, ErrMergeCandidateNotInProposal
				}
			}
		}
		// Proposal evidence has a controlled shape; omit arbitrary source metadata.
		safe := map[string]any{"proposal_id": row.ID, "status": row.Changes["status"], "reason": row.Changes["reason"], "candidates": row.Changes["candidates"], "source": row.Source, "source_kind": row.Changes["source_kind"], "proposed_at": row.ProposedAt, "latest_evidence_at": row.Changes["latest_evidence_at"]}
		b, _ := json.Marshal(redact.Map(safe))
		evidence = append(evidence, b)
	}
	if !foundProposal {
		return nil, ErrMergeProposalNotFound
	}
	out := &AssetMergePreview{MergeSelection: in, Assets: []MergePreviewAsset{}, Conflicts: []MergeFieldConflict{}, SelectedFields: map[string]any{}, Children: []MergeChildCount{}, Evidence: evidence}
	var survivor map[string]any
	for _, a := range snap.Assets {
		safe := map[string]any{}
		for _, f := range mergeSnapshotFields {
			safe[f] = redact.Any(a[f])
		}
		id, _ := uuid.Parse(a["id"].(string))
		out.Assets = append(out.Assets, MergePreviewAsset{AssetID: id, DisplayName: mergeString(a["display_name"]), Hostname: mergeString(a["hostname"]), ClassKey: mergeString(a["class_key"]), AssetStatus: mergeString(a["asset_status"]), IdentityStatus: mergeString(a["identity_status"]), Fields: safe})
		if id == in.SurvivorAssetID {
			survivor = a
		}
	}
	for _, field := range mergeEditableFields {
		value := survivor[field]
		values := []MergeFieldValue{}
		distinct := map[string]bool{}
		declared := false
		for _, a := range snap.Assets {
			if mergeEmpty(a[field]) {
				continue
			}
			id, _ := uuid.Parse(a["id"].(string))
			d := mergeDeclared(a, field)
			values = append(values, MergeFieldValue{AssetID: id, Value: redact.Any(a[field]), Declared: d})
			b, _ := json.Marshal(a[field])
			distinct[string(b)] = true
			declared = declared || d
		}
		if len(distinct) > 1 {
			out.Conflicts = append(out.Conflicts, MergeFieldConflict{Field: field, Values: values, RequiresResolution: declared})
		}
		if choice, ok := in.FieldResolutions[field]; ok {
			for _, a := range snap.Assets {
				if a["id"] == choice.String() {
					value = a[field]
				}
			}
		} else if mergeEmpty(value) && len(distinct) == 1 && len(values) > 0 {
			// Public conflict values are redacted; the persisted default must
			// come from the original source record, never that projection.
			for _, asset := range snap.Assets {
				if asset["id"] == values[0].AssetID.String() {
					value = asset[field]
					break
				}
			}
		}
		out.SelectedFields[field] = value
	}
	if selectedClass, chosen := in.FieldResolutions["class_key"]; chosen {
		for _, asset := range snap.Assets {
			if asset["id"] == selectedClass.String() {
				if _, explicitAttributes := in.FieldResolutions["attributes"]; !explicitAttributes {
					out.SelectedFields["attributes"] = asset["attributes"]
				}
			}
		}
	}
	if err := addManagementPreview(out, snap); err != nil {
		return nil, err
	}
	tables := make([]string, 0, len(snap.Records))
	for table := range snap.Records {
		tables = append(tables, table)
	}
	sort.Strings(tables)
	for _, table := range tables {
		if table != "assets" {
			out.Children = append(out.Children, MergeChildCount{Table: table, Count: len(snap.Records[table])})
		}
	}
	revision, _ := json.Marshal(struct {
		Selection        MergeSelection
		Proposal         uuid.UUID
		Records          map[string][]mergeRecord
		Proposals        []json.RawMessage
		EnrichmentPolicy mergeEnrichmentPolicy
	}{in, proposal, snap.Records, snap.Proposals, snap.EnrichmentPolicy})
	sum := sha256.Sum256(revision)
	out.Revision = hex.EncodeToString(sum[:])
	out.selectedRaw = out.SelectedFields
	out.SelectedFields = redact.Map(out.SelectedFields)
	return out, nil
}
func mergeString(v any) string { s, _ := v.(string); return s }
func mergeEmpty(v any) bool {
	if v == nil {
		return true
	}
	switch value := v.(type) {
	case string:
		return value == ""
	case map[string]any:
		return len(value) == 0
	case []any:
		return len(value) == 0
	}
	return false
}

func mergeDeclared(a map[string]any, field string) bool {
	if field == "class_key" {
		return a["class_source_kind"] == "declared"
	}
	if field == "display_name" || field == "hostname" {
		metadata, _ := a["metadata"].(map[string]any)
		kind, _ := metadata["name_source_kind"].(string)
		return kind == "declared" || a["_legacy_name_declared"] == true
	}
	// Placement and administrative fields may be operator-owned even on legacy assets.
	return field != "primary_address"
}
