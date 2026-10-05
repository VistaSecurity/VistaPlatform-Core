package services

// DeviceService is the Devices page's store, on the phase-1 asset model.
//
// Nothing here writes `devices` any more — the table is gone (ADR-0002 D5). A
// device is an asset with an `asset_management` row; see managed_asset.go for
// the column map and the reasoning behind the two places it deviates from
// DATA_MODEL §2's literal text.
//
// The HTTP surface is unchanged on purpose: the routes are still /devices/…
// and the payload is still a Device. What changed underneath is that `id` is
// now the ASSET id (and is repeated as `asset_id`, so a client does not have to
// infer it), and that creating a device runs the operator's input through the
// identification engine instead of inserting a row. A FortiGate an operator
// adds here and the same FortiGate the sensor sees on the wire now resolve to
// one asset — which is the whole point of the change, and was impossible while
// `devices` was a second asset table with no link to the first.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/security/credentials"
)

// errDeviceHasNoIdentifier is returned for a device the engine could never
// recognise again.
//
// An identifier-less asset is not a cheap asset; it is one that every later
// observation of the same thing creates again. A device with no hostname, no
// address, no management URL and no serial is exactly that, and refusing it is
// better than silently minting a duplicate on every interrogation.
var errDeviceHasNoIdentifier = errors.New("a device needs a hostname, an address, a management URL or a serial number")

// ErrDeviceNotFound is returned when no managed asset matches. A missing asset
// and an asset in another tenant are deliberately the same error.
var ErrDeviceNotFound = errors.New("device not found")

// ErrDeviceIdentityContested means every identifier the operator supplied
// already belongs to a different asset.
//
// Nothing is created: a merge proposal is waiting in Approvals, and that is the
// right place for "you have just told me two things you thought were separate
// are one". Creating a third asset to hang the management row off would be the
// auto-merge ADR-0002 D5 forbids, approached from the other side.
//
// It is a SENTINEL, matched with errors.Is. The value callers actually receive
// is a *DeviceIdentityContestedError carrying the proposal id.
var ErrDeviceIdentityContested = errors.New(
	"every identifier for this device already belongs to another asset; review the merge proposal in Approvals")

// DeviceIdentityContestedError is the contested outcome, with the proposal id
// the operator is being sent to read.
//
// # Why this is a value and not an error returned from the transaction
//
// The engine writes the merge proposal INSIDE the resolve transaction. Returning
// an error from the RunInTx closure rolls that transaction back — so the
// proposal the operator was just told to go and review was erased by the very
// act of telling them. The closure now returns nil on a zero ref, the
// transaction COMMITS with the proposal in it, and the contested outcome is
// mapped to an error out here where it can no longer undo anything.
type DeviceIdentityContestedError struct {
	// ProposalID names the merge proposal in Approvals. Empty only if the
	// engine somehow produced a contested outcome without one.
	ProposalID string
	// Candidates is how many existing assets the identifiers resolved to.
	Candidates int
}

func (e *DeviceIdentityContestedError) Error() string {
	if e.ProposalID == "" {
		return ErrDeviceIdentityContested.Error()
	}
	return fmt.Sprintf("every identifier for this device already belongs to another asset "+
		"(%d candidate(s)); review merge proposal %s in Approvals", e.Candidates, e.ProposalID)
}

// Is makes errors.Is(err, ErrDeviceIdentityContested) true for this type, so a
// caller can test the CONDITION without reaching for the id.
func (e *DeviceIdentityContestedError) Is(target error) bool {
	return target == ErrDeviceIdentityContested
}

// contestedFrom builds the error from a resolution that wrote nothing.
func contestedFrom(res identity.Resolution) *DeviceIdentityContestedError {
	return &DeviceIdentityContestedError{ProposalID: res.Proposal.ID, Candidates: len(res.Candidates)}
}

// devicePasswordPolicy names the one field of a device's stored credentials
// that is a secret. `asset_credentials` is columns rather than a config blob,
// so the policy has exactly one entry and EncryptValue is used directly; the
// Policy is still declared because NewCipher takes one and because the next
// column added here should have to be classified rather than defaulted.
var devicePasswordPolicy = credentials.Policy{Fields: []string{"password"}}

// DeviceService handles device business logic.
type DeviceService struct {
	db *sql.DB

	// cipher seals asset_credentials.password_enc. The column name is the
	// contract — it holds ciphertext, always — and scripts/audit-credential-
	// encryption.mjs enforces that this file imports the shared helper.
	cipher *credentials.Cipher

	// The fact, history and admission-mode store (asset_facts,
	// asset_history, tenant settings). Never used to resolve identity:
	// identification is inventory-service's (sighting_poster.go).
	storeOnce sync.Once
	store     *pgidentity.Repository
}

// NewDeviceService creates a device service keyed from the environment.
func NewDeviceService(db *sql.DB) *DeviceService {
	return NewDeviceServiceWithKey(db, os.Getenv("ENCRYPTION_MASTER_KEY"))
}

// NewDeviceServiceWithKey creates a device service with an explicit master key.
//
// Callers that already hold the key (CloudDiscoveryService) pass it rather than
// re-reading the environment, and tests pass their own — which is why this is a
// constructor and not a settable field: a cipher built once at construction
// cannot be half-configured by a caller that forgot to set the key after the
// fact.
func NewDeviceServiceWithKey(db *sql.DB, masterKey string) *DeviceService {
	if masterKey == "" {
		// Fallback for development - in production this should fail.
		// Deliberately not "": NewCipher("") is a DISABLED, pass-through cipher,
		// which would store the operator's device password in the clear in a
		// column whose name promises ciphertext.
		masterKey = "dev-encryption-key-change-in-production"
	}
	cipher, err := credentials.NewCipher("asset_credentials", masterKey, devicePasswordPolicy)
	if err != nil {
		// A master key that will not initialise is a configuration failure, not
		// a reason to store credentials in the clear. Leaving cipher nil makes
		// every write that needs it fail loudly at the call site.
		log.Printf("[DeviceService] credential cipher unavailable, device credentials cannot be stored: %v", err)
	}
	return &DeviceService{db: db, cipher: cipher}
}

// encryptPassword seals a device password for asset_credentials.password_enc.
func (s *DeviceService) encryptPassword(password string) (string, error) {
	if password == "" {
		return "", nil
	}
	if s.cipher == nil {
		return "", fmt.Errorf("credential encryption is unavailable; refusing to store a device password")
	}
	return s.cipher.EncryptValue(password)
}

// maskPassword masks a password for display in API responses
func maskPassword(password string) string {
	if len(password) == 0 {
		return ""
	}
	if len(password) > 8 {
		return password[:4] + "****" + password[len(password)-4:]
	}
	return "****"
}

// ---------------------------------------------------------------------------
// identification
// ---------------------------------------------------------------------------

// resolveSighting posts one sighting to inventory-service and then, once the
// engine's decision is committed there, runs `after` on ONE transaction of
// this service's with the repository bound to it: the management row, the
// credentials, the declared facts, the retained context.
//
// It used to be one transaction — the engine's — for both halves. The engine
// is inventory-service's now (platform ADR-0003 D3), so the identity half
// (asset, identifiers, history, the tenant's auto-accept threshold, the retry
// on a racing identifier claim, the audit event for an auto-accepted merge)
// commits there and this half commits here. What that costs: a failure in
// `after` leaves the identity decision standing without its configuration.
// Every write in `after` is an upsert, and the operator's retry (or the next
// run of the cloud collector) re-posts a sighting that MATCHES the asset that
// now exists and re-runs `after` — the repair the old single transaction made
// unnecessary.
//
// A resolution that wrote nothing — the floor's contested path, or evidence
// held for review — hands `after` a ZERO ref. The callback is still run, and
// must check [identity.AssetRef.Zero] before writing anything about "the"
// asset.
func (s *DeviceService) resolveSighting(
	ctx context.Context,
	sighting identity.Sighting,
	after func(r *pgidentity.Repository, res identity.Resolution) error,
) (identity.Resolution, error) {
	_, res, err := postSighting(ctx, s.db, sighting)
	if err != nil {
		return identity.Resolution{}, err
	}
	if after == nil {
		return res, nil
	}
	if err := s.Repo().RunInTx(ctx, sighting.TenantID, func(r *pgidentity.Repository) error {
		return after(r, res)
	}); err != nil {
		return res, err
	}
	return res, nil
}

// Repo is the fact, history and settings store the interrogation paths in
// this package write through, so they do not each open their own. It never
// resolves identity.
func (s *DeviceService) Repo() *pgidentity.Repository {
	s.storeOnce.Do(func() { s.store = pgidentity.New(s.db) })
	return s.store
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

// CreateDevice resolves the operator's input to an asset and configures
// management on it.
//
// It is NOT an insert. The operator is telling us a device exists at an
// address; whether that is a host we already know about is the identification
// engine's question, and routing it there is what stops a manually-added
// FortiGate from becoming a second row for a host the sensor already found.
//
// Consequence worth knowing: an asset the engine CREATES here is
// `pending_approval`, because the engine never approves (ADR-0002 D3, and an
// engine that could approve its own creations would be the auto-merge D5
// forbids wearing a different hat). The device appears on the Devices page
// immediately — that page is a filter on asset_management and does not look at
// approval status — while the asset itself waits in Approvals like any other
// discovery. Auto-approving a DECLARED device is a reasonable rule and it
// belongs in the approvals workstream, not here.
//
// Identification and configuration are ONE unit of work. The engine's writes —
// the asset, its identifiers, its last-seen, its history — and this service's —
// the management row, the credentials, the declared facts — run on the same
// transaction, through [pgidentity.Repository.Tx]. One observation is one fact
// about the world: an asset whose history says it was created and whose
// management configuration is absent is a state no later run repairs, because
// the next observation MATCHES the asset that exists and never takes the create
// path again.
func (s *DeviceService) CreateDevice(ctx context.Context, tenantID uuid.UUID, req models.CreateDeviceRequest) (*models.Device, error) {
	discoveryMethod := req.DiscoveryMethod
	if discoveryMethod == "" {
		discoveryMethod = "device_interrogation"
	}
	now := time.Now().UTC()

	sighting, err := deviceSighting(tenantID, deviceSightingInput{
		deviceObservationInput: deviceObservationInput{
			DeviceType:      req.DeviceType,
			Hostname:        derefStr(req.Hostname),
			IPAddress:       derefStr(req.IPAddress),
			ManagementURL:   derefStr(req.ManagementURL),
			SerialNumber:    derefStr(req.SerialNumber),
			CloudResourceID: cloudResourceIDFromMetadata(req.Metadata),
			DiscoveryMethod: discoveryMethod,
			Source:          declaredSource(),
			ObservedAt:      now,
			Admission:       probeEvidence(req.ProbeEvidence),
		},
		ProbeMACAddress:     req.ProbeMACAddress,
		ProbeRead:           req.ProbeRead,
		ProbeSSHHostKey:     req.ProbeSSHHostKeyFingerprint,
		ProbeSSHHostKeyType: req.ProbeSSHHostKeyType,
	})
	if err != nil {
		return nil, err
	}

	fields := deviceFieldUpdate{
		DeviceType:              req.DeviceType,
		Hostname:                req.Hostname,
		IPAddress:               req.IPAddress,
		ManagementURL:           req.ManagementURL,
		Vendor:                  req.Vendor,
		Model:                   req.Model,
		FirmwareVersion:         req.FirmwareVersion,
		TLSInsecureSkipVerify:   sshSafeSkipFlag(req.DeviceType, req.TLSInsecureSkipVerify),
		CredentialID:            req.CredentialID,
		Username:                req.Username,
		Password:                req.Password,
		Metadata:                req.Metadata,
		Tags:                    req.Tags,
		DiscoveryMethod:         discoveryMethod,
		CreateManagement:        true,
		PlatformReinterrogation: req.PlatformReinterrogationAllowed,
	}

	// The configuration half commits in a transaction of its own after the
	// identity half has committed in inventory-service, so anything about it
	// that can be known to fail is refused BEFORE the sighting is sent: an
	// asset with no management configuration is a state no later run repairs.
	if err := fields.preflight(); err != nil {
		return nil, fmt.Errorf("failed to record device: %w", err)
	}

	var assetID uuid.UUID
	res, err := s.resolveSighting(ctx, sighting, func(r *pgidentity.Repository, res identity.Resolution) error {
		if res.Asset.Zero() {
			// The floor's contested path, or evidence held for review: nothing
			// was created and there is nothing to configure — except, for a held
			// observation, the configuration to install once it is linked.
			// The outcome is mapped after the commit.
			return s.retainManagement(ctx, r, sighting.TenantID, res, fields)
		}
		parsed, parseErr := uuid.Parse(res.Asset.ID)
		if parseErr != nil {
			return fmt.Errorf("identification returned an unusable asset id %q: %w", res.Asset.ID, parseErr)
		}
		assetID = parsed
		return s.applyDeviceFields(ctx, r, tenantID, assetID, fields)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to record device: %w", err)
	}
	if res.Asset.Zero() {
		if res.ObservationID != "" {
			return nil, &identity.RetainedObservation{Result: res.IngestResult()}
		}
		return nil, contestedFrom(res)
	}

	return s.GetDevice(ctx, tenantID, assetID)
}

// deviceFieldUpdate is the set of Device fields a create or update is writing.
// Nil means "not mentioned"; see managementUpsert for why that distinction is
// kept rather than flattened to the zero value.
type deviceFieldUpdate struct {
	DeviceType            string
	Hostname              *string
	IPAddress             *string
	ManagementURL         *string
	Vendor                *string
	Model                 *string
	FirmwareVersion       *string
	SerialNumber          *string
	TLSInsecureSkipVerify *bool
	ConnectionStatus      *string
	CredentialID          *uuid.UUID
	Username              *string
	Password              *string
	Metadata              map[string]interface{}
	Tags                  map[string]interface{}
	DiscoveryMethod       string
	CreateManagement      bool
	// PlatformReinterrogation is the explicit consent field (see
	// PlatformReinterrogationKey). Nil means "not mentioned".
	PlatformReinterrogation *bool
	// Unmanaged says this observation configures NO management at all: no
	// asset_management row and no asset_credentials row. It is what cloud
	// discovery sets on everything it finds — see upsertDeviceAssetWith for why
	// nothing reached through a cloud API is a managed device.
	//
	// It is not `CreateManagement: false`. That flag only withholds the default
	// `unknown` status; upsertManagement would still insert a row, and an asset
	// with an asset_management row is by definition on the Devices page
	// (ListDevices is the inner join on it).
	//
	// Both rows go together deliberately. asset_credentials is reachable only
	// through asset_management or an interrogation — agent_job_credentials.go,
	// device_interrogation_service.go and managed_asset.go all join through one
	// of those — so a credentials row on an unmanaged asset is unreachable by
	// every consumer. What it held for a cloud resource was the integration id
	// and nothing else, and that is kept as provenance under
	// cloudIntegrationIDKey in the asset's metadata.
	Unmanaged bool
}

// preflight refuses a field update that applyDeviceFields would fail to write
// for a reason knowable before anything is written: metadata or tags that do
// not serialise.
func (in deviceFieldUpdate) preflight() error {
	for name, v := range map[string]map[string]interface{}{"metadata": in.Metadata, "tags": in.Tags} {
		if len(v) == 0 {
			continue
		}
		if _, err := json.Marshal(v); err != nil {
			return fmt.Errorf("device %s cannot be stored: %w", name, err)
		}
	}
	return nil
}

// applyDeviceFields writes everything about a device that is not its identity:
// the management row, the credentials, the declared hardware facts, and the
// pipeline metadata.
func (s *DeviceService) applyDeviceFields(ctx context.Context, r *pgidentity.Repository, tenantID, assetID uuid.UUID, in deviceFieldUpdate) error {
	tx := r.Tx()
	if tx == nil {
		// Unreachable: every caller goes through RunInTx, which binds the
		// repository. Saying so loudly beats silently opening a second
		// transaction and losing the atomicity this signature exists for.
		return fmt.Errorf("applyDeviceFields needs a bound repository; the caller did not run inside RunInTx")
	}
	if err := setAssetAddress(ctx, tx, tenantID, assetID, derefStr(in.Hostname), derefStr(in.IPAddress)); err != nil {
		return fmt.Errorf("failed to record device address: %w", err)
	}

	// The free-form metadata can neither grant nor withdraw the platform
	// re-interrogation consent; only its explicit field can. The merge below
	// replaces the nested map wholesale — with whatever key the client put in
	// it — so whenever it runs, the consent is read first and written back
	// afterwards (applyPlatformReinterrogation): the requested value if the
	// request names one, the prior value otherwise.
	metadata := in.Metadata
	consentTouched := in.PlatformReinterrogation != nil || len(metadata) > 0
	var priorConsent bool
	if consentTouched {
		var err error
		if priorConsent, err = readPlatformReinterrogation(ctx, tx, tenantID, assetID); err != nil {
			return err
		}
	}

	metaPatch := map[string]interface{}{}
	if strings.TrimSpace(in.DeviceType) != "" {
		metaPatch[deviceTypeKey] = strings.ToLower(strings.TrimSpace(in.DeviceType))
	}
	if len(metadata) > 0 {
		metaPatch[deviceMetadataKey] = metadata
	}
	if in.DiscoveryMethod != "" {
		metaPatch[deviceDiscoveryMethodKey] = in.DiscoveryMethod
	}
	if err := mergeAssetMetadata(ctx, tx, tenantID, assetID, metaPatch); err != nil {
		return fmt.Errorf("failed to record device metadata: %w", err)
	}
	if err := mergeAssetTags(ctx, tx, tenantID, assetID, in.Tags); err != nil {
		return fmt.Errorf("failed to record device tags: %w", err)
	}
	if consentTouched {
		if err := applyPlatformReinterrogation(ctx, tx, tenantID, assetID, in.PlatformReinterrogation, priorConsent); err != nil {
			return err
		}
	}

	// An unmanaged observation writes neither row — not an empty management row,
	// not one defaulted to `unknown`. The row's EXISTENCE is the claim, because
	// the Devices page is the inner join on it.
	if !in.Unmanaged {
		mgmt := managementUpsert{
			ManagementURL:         in.ManagementURL,
			TLSInsecureSkipVerify: in.TLSInsecureSkipVerify,
			ConnectionStatus:      in.ConnectionStatus,
		}
		if proto := managementProtocol(derefStr(in.ManagementURL), in.DeviceType); proto != "" {
			mgmt.ManagementProtocol = &proto
		}
		if in.CreateManagement && mgmt.ConnectionStatus == nil {
			unknown := "unknown"
			mgmt.ConnectionStatus = &unknown
		}
		if err := upsertManagement(ctx, tx, tenantID, assetID, mgmt); err != nil {
			return err
		}
		if err := s.upsertDeviceCredentials(ctx, tx, tenantID, assetID, in); err != nil {
			return err
		}
	}

	// Declared hardware identity. The form's vendor/model/firmware are what a
	// person asserted; an interrogation writes the same keys as an active
	// measurement under its own source_ref, and ADR-0002 D4's identity ladder
	// decides which one the Devices page shows.
	ref := identity.AssetRef{TenantID: tenantID.String(), ID: assetID.String()}
	if fs := deviceFacts(derefStr(in.Vendor), derefStr(in.Model), derefStr(in.FirmwareVersion), declaredSource(), time.Now().UTC()); len(fs) > 0 {
		if err := r.UpsertFacts(ctx, ref, facts.ProducerDeviceInterrogation, fs); err != nil {
			return fmt.Errorf("failed to record device identity facts: %w", err)
		}
	}

	// A serial supplied on an UPDATE is identity, not configuration: it goes
	// to the engine with the update's sighting (UpdateDevice), never straight
	// into asset_identifiers.
	return nil
}

// upsertDeviceCredentials writes asset_credentials.
//
// password_enc holds CIPHERTEXT, always — the column name is the contract. The
// value is sealed by the shared credentials helper (tagged `enc:v1:`), which is
// what `devices.password` never was: it held bare encryption.Service output
// with no marker, so every reader had to guess whether a value was encrypted.
func (s *DeviceService) upsertDeviceCredentials(ctx context.Context, tx *sql.Tx, tenantID, assetID uuid.UUID, in deviceFieldUpdate) error {
	if in.CredentialID == nil && in.Username == nil && (in.Password == nil || *in.Password == "") {
		return nil
	}
	var encrypted *string
	if in.Password != nil && *in.Password != "" {
		sealed, err := s.encryptPassword(*in.Password)
		if err != nil {
			return fmt.Errorf("failed to encrypt password: %w", err)
		}
		encrypted = &sealed
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO public.asset_credentials (
			tenant_id, asset_id, credential_id, username, password_enc
		) VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (tenant_id, asset_id) DO UPDATE
		SET credential_id = coalesce($3, public.asset_credentials.credential_id),
		    username      = coalesce($4, public.asset_credentials.username),
		    password_enc  = coalesce($5, public.asset_credentials.password_enc),
		    updated_at    = now()`,
		tenantID, assetID, in.CredentialID, in.Username, encrypted)
	if err != nil {
		return fmt.Errorf("upsert asset_credentials: %w", err)
	}
	return nil
}

// GetDevice retrieves one managed asset, scoped to tenantID.
func (s *DeviceService) GetDevice(ctx context.Context, tenantID, assetID uuid.UUID) (*models.Device, error) {
	devices, err := s.queryDevices(ctx, tenantID, " AND a.id = $2", assetID)
	if err != nil {
		return nil, err
	}
	if len(devices) == 0 {
		return nil, ErrDeviceNotFound
	}
	return devices[0], nil
}

// ListDevices lists the tenant's assets that have management configured.
//
// The INNER JOIN in managedAssetSelect IS the Devices page: "an asset with an
// asset_management row" is the definition of a device now, so the page's
// contents and the table's contents are the same statement.
func (s *DeviceService) ListDevices(ctx context.Context, tenantID uuid.UUID) ([]*models.Device, error) {
	return s.queryDevices(ctx, tenantID, " ORDER BY a.created_at DESC")
}

func (s *DeviceService) queryDevices(ctx context.Context, tenantID uuid.UUID, suffix string, args ...interface{}) ([]*models.Device, error) {
	var devices []*models.Device
	queryArgs := append([]interface{}{tenantID}, args...)
	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		devices = devices[:0]
		rows, err := tx.QueryContext(ctx, managedAssetSelect+suffix, queryArgs...)
		if err != nil {
			return fmt.Errorf("failed to list devices: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			row, scanErr := scanManagedAsset(rows.Scan)
			if scanErr != nil {
				return fmt.Errorf("failed to scan device: %w", scanErr)
			}
			d := row.device
			devices = append(devices, &d)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	if err := s.hydrateDeviceIdentity(ctx, tenantID, devices); err != nil {
		return nil, err
	}
	if err := s.hydrateInterrogatedByAgent(ctx, tenantID, devices); err != nil {
		return nil, err
	}
	return devices, nil
}

// UpdateDevice updates a managed asset's management, credentials and declared
// identity.
func (s *DeviceService) UpdateDevice(ctx context.Context, tenantID, assetID uuid.UUID, req models.UpdateDeviceRequest) (*models.Device, error) {
	existing, err := s.GetDevice(ctx, tenantID, assetID)
	if err != nil {
		return nil, err
	}

	fields := deviceFieldUpdate{
		// The device type is not editable through this path today and is read
		// back off the asset so managementProtocol resolves the same way it did
		// at creation.
		DeviceType:            existing.DeviceType,
		Hostname:              req.Hostname,
		IPAddress:             req.IPAddress,
		ManagementURL:         req.ManagementURL,
		Vendor:                req.Vendor,
		Model:                 req.Model,
		FirmwareVersion:       req.FirmwareVersion,
		SerialNumber:          req.SerialNumber,
		TLSInsecureSkipVerify: sshSafeSkipFlag(existing.DeviceType, req.TLSInsecureSkipVerify),
		ConnectionStatus:      req.ConnectionStatus,
		CredentialID:          req.CredentialID,
		Username:              req.Username,
		Password:              req.Password,
		Metadata:              req.Metadata,
		Tags:                  req.Tags,

		PlatformReinterrogation: req.PlatformReinterrogationAllowed,
	}

	// Identity first: a hostname, address or serial the operator typed is a
	// statement about WHICH device this is, and the engine decides what it
	// means ( item 4). It used to be attached straight onto the asset
	// with no scope check, and a value another asset owned was logged and
	// skipped while the operator was told the edit succeeded. Now it is a
	// declared sighting bound to this device through the identifiers it
	// already holds (knownAssetIdentifiers): a value nobody owns attaches to
	// it, one another asset owns opens a merge proposal for a human.
	if err := s.postDeviceUpdate(ctx, tenantID, assetID, derefStr(req.Hostname), derefStr(req.IPAddress), derefStr(req.SerialNumber)); err != nil {
		return nil, err
	}

	// Then the configuration, on one transaction: the management row, the
	// credentials and the declared facts land together or not at all.
	err = s.Repo().RunInTx(ctx, tenantID.String(), func(r *pgidentity.Repository) error {
		return s.applyDeviceFields(ctx, r, tenantID, assetID, fields)
	})
	if err != nil {
		return nil, err
	}

	return s.GetDevice(ctx, tenantID, assetID)
}

// postDeviceUpdate sends an operator's identity edit to the engine. Nothing
// to send is not an error.
func (s *DeviceService) postDeviceUpdate(ctx context.Context, tenantID, assetID uuid.UUID, hostname, ip, serial string) error {
	sighting, ok := deviceUpdateSighting(tenantID, time.Now().UTC(), hostname, ip, serial)
	if !ok {
		return nil
	}
	r, res, err := postDeclaration(ctx, s.db, sighting, assetID.String())
	if err != nil {
		return fmt.Errorf("failed to record the device's identity: %w", err)
	}
	if res.Outcome == identity.OutcomeConflict {
		// Nothing was written: a value the operator typed belongs to another
		// asset (a merge proposal is open), or is a second serial for a device
		// that has one. The edit is refused whole, configuration included, as
		// the identifier edit refuses it.
		return &DeviceIdentifierConflictError{ProposalID: r.ProposalID, Reasons: r.Reasons}
	}
	return nil
}

// DeviceIdentifierConflictError refuses a Devices-form edit whose hostname,
// address or serial the engine would not attach to the device: another asset
// owns it (ProposalID names the merge proposal opened for a human), or the
// device already holds a different serial. Nothing was written.
type DeviceIdentifierConflictError struct {
	ProposalID string
	Reasons    []string
}

func (e *DeviceIdentifierConflictError) Error() string {
	if e.ProposalID != "" {
		return "a value in this edit already belongs to another asset; review merge proposal " + e.ProposalID + " in Approvals"
	}
	return "this device already holds a different serial number; nothing was changed"
}

// DeleteDevice stops managing an asset.
//
// It removes the `asset_management` and `asset_credentials` rows and LEAVES THE
// ASSET. That is a deliberate change of meaning, and the honest one: the host
// did not cease to exist because an operator removed its management
// configuration, and the same host is very likely also known to the sensor.
// Deleting the asset would throw away its endpoints, its crypto configurations,
// its findings and its history — an inventory-wide deletion triggered from a
// page whose button says "remove device".
//
// It is recorded in asset_history rather than happening silently: unmanaging an
// asset changes what the platform will do with it, and "nothing is decided
// silently" is the rule the whole identity layer is built on.
func (s *DeviceService) DeleteDevice(ctx context.Context, tenantID, assetID uuid.UUID) error {
	var removed int64
	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		res, e := tx.ExecContext(ctx, `
			DELETE FROM public.asset_management WHERE tenant_id = $1 AND asset_id = $2`, tenantID, assetID)
		if e != nil {
			return e
		}
		removed, e = res.RowsAffected()
		if e != nil {
			return e
		}
		if removed == 0 {
			return nil
		}
		_, e = tx.ExecContext(ctx, `
			DELETE FROM public.asset_credentials WHERE tenant_id = $1 AND asset_id = $2`, tenantID, assetID)
		return e
	})
	if err != nil {
		return fmt.Errorf("failed to delete device: %w", err)
	}
	if removed == 0 {
		return ErrDeviceNotFound
	}

	if histErr := s.Repo().RecordHistory(ctx, identity.HistoryEntry{
		TenantID: tenantID.String(),
		AssetID:  assetID.String(),
		Action:   identity.ActionUpdated,
		Source:   declaredSource(),
		Changes:  map[string]any{"management": "removed", "credentials": "removed"},
		At:       time.Now().UTC(),
	}); histErr != nil {
		// The management row is already gone; losing the history entry is worth
		// a warning, not an error that tells the operator the delete failed.
		log.Printf("[DeviceService] failed to record unmanage history for asset %s: %v", assetID, histErr)
	}
	return nil
}

// ---------------------------------------------------------------------------
// stored credentials
// ---------------------------------------------------------------------------

// StoredDeviceCredentials carries a device's stored credentials exactly as they
// sit in `asset_credentials`: username in the clear, password still ciphertext.
//
// GetDevice deliberately MASKS the password before returning
// (maskPassword → "abcd****wxyz") because *models.Device is serialised straight
// into API responses. That masking is right for the API and catastrophic for
// anything that needs the real value: the interrogation handler used
// device.Password from GetDevice as the credential it shipped to the agent, so
// what a remote agent actually received was a twelve-character fragment of a
// ciphertext. Anything that needs the true stored value must come
// through here instead, and this type must never be returned from a handler.
type StoredDeviceCredentials struct {
	Username string
	// EncryptedPassword is ciphertext, NOT plaintext — tagged `enc:v1:` by the
	// shared credentials helper. NormalizeJobCredentials opens it at agent
	// hand-off, where the master key lives.
	EncryptedPassword  string
	ManagementURL      string
	DeviceType         string
	InsecureSkipVerify bool
}

// HasCredentials reports whether the device carries embedded credentials.
func (c StoredDeviceCredentials) HasCredentials() bool {
	return c.Username != "" && c.EncryptedPassword != ""
}

// GetStoredDeviceCredentials reads a managed asset's credentials unmasked,
// scoped to tenantID.
func (s *DeviceService) GetStoredDeviceCredentials(ctx context.Context, tenantID, assetID uuid.UUID) (StoredDeviceCredentials, error) {
	var creds StoredDeviceCredentials
	var username, password, managementURL sql.NullString
	var metaJSON []byte
	found := false

	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		scanErr := tx.QueryRowContext(ctx, `
			SELECT c.username, c.password_enc, m.management_url,
			       m.tls_insecure_skip_verify, a.metadata
			FROM public.assets a
			JOIN public.asset_management m ON m.tenant_id = a.tenant_id AND m.asset_id = a.id
			LEFT JOIN public.asset_credentials c ON c.tenant_id = a.tenant_id AND c.asset_id = a.id
			WHERE a.tenant_id = $1 AND a.id = $2 AND a.deleted_at IS NULL`,
			tenantID, assetID).Scan(&username, &password, &managementURL, &creds.InsecureSkipVerify, &metaJSON)
		if errors.Is(scanErr, sql.ErrNoRows) {
			return nil
		}
		if scanErr != nil {
			return scanErr
		}
		found = true
		return nil
	})
	if err != nil {
		return StoredDeviceCredentials{}, fmt.Errorf("failed to read device credentials: %w", err)
	}
	if !found {
		return StoredDeviceCredentials{}, ErrDeviceNotFound
	}

	creds.Username = username.String
	creds.EncryptedPassword = password.String
	creds.ManagementURL = managementURL.String
	creds.DeviceType = deviceTypeFromMetadata(metaJSON)
	return creds, nil
}

func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// cloudResourceIDFromMetadata digs the provider's own resource id out of a
// device's metadata. ARN, Azure resource id and GCP self-link are the same
// thing under three names, and it is the strongest identifier a cloud resource
// ever has.
//
// The key list lives in shared/identity so this and inventory-service's ingest
// path read the SAME one. They used to keep private copies, the copies drifted,
// and the two sides then disagreed about which resource a row named — see
// identity.CloudResourceIDKeys.
func cloudResourceIDFromMetadata(meta map[string]interface{}) string {
	return identity.CloudResourceIDFromMetadata(meta)
}

// probeEvidence is the admission evidence a create carries: none for a device
// typed in by hand, and what Add device's own authenticated identification
// established otherwise (see DiscoveredDeviceInfo.ApplyTo).
func probeEvidence(e *identity.AdmissionEvidence) identity.AdmissionEvidence {
	if e == nil {
		return identity.AdmissionEvidence{}
	}
	return *e
}

// sshSafeSkipFlag is the TLS skip flag as it may be STORED for deviceType. For
// an SSH-managed type it is always an explicit false — including when the
// request did not mention it, so any edit of a Cisco device stored with the
// flag set clears it ( review B1/NB-7).
func sshSafeSkipFlag(deviceType string, requested *bool) *bool {
	if !IsSSHManagedDeviceType(deviceType) {
		return requested
	}
	off := false
	return &off
}

// PinSSHHostKeyIfUnset pins the SSH host key an Add-device identification
// authenticated through, unless the device already has one pinned (
// review NB-6). Without it the first interrogation trusted whatever answered
// on first use a second time.
func (s *DeviceService) PinSSHHostKeyIfUnset(ctx context.Context, tenantID, assetID uuid.UUID, fingerprint, keyType string) (bool, error) {
	return pinSSHHostKeyIfUnset(ctx, s.db, tenantID, assetID, fingerprint, keyType)
}

// ResetSSHHostKeyPin clears the SSH host key pinned to a managed asset, so the
// next interrogation enrols the key the device presents (H7).
//
// The operator-facing half of fail-closed host-key verification: a device that
// was legitimately replaced or rekeyed has to be able to come back without
// anybody disabling the check.
func (s *DeviceService) ResetSSHHostKeyPin(ctx context.Context, tenantID, assetID uuid.UUID) error {
	return clearSSHHostKeyPin(ctx, s.db, tenantID, assetID)
}
