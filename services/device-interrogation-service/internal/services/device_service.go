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
	"github.com/vistasecurity/vistaplatform/shared/identity/identityaudit"
	"github.com/vistasecurity/vistaplatform/shared/identity/identitysettings"
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

	identityOnce sync.Once
	identityRepo *pgidentity.Repository
	identityEng  *identity.Engine
	identityErr  error
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

// identityEngine returns the engine, building it on first use.
//
// AutoAcceptThreshold is left at zero HERE and supplied PER OBSERVATION by
// resolveObservation, from the tenant's own setting (workstream 4.6a). It has
// to be per-observation: the engine is built once per process and serves every
// tenant, so a threshold fixed here would be one tenant's decision applied to
// all of them, and a tenant turning auto-accept off would keep auto-merging
// until the next deploy.
//
// Until 4.6a this service read the setting at all, and zero was the answer for
// every tenant — so a tenant who set 95% got auto-accepted merges on the
// inventory intake path and never on the interrogation one. That failed closed,
// but the same HOST reaches both services, so which engine happened to resolve a
// sighting decided whether the tenant's threshold applied to it. The four fences
// that govern an auto-accept are [identity.Engine]'s and always were; what was
// missing was the number.
//
// Merge proposals raised here are SCORED and explained whatever the threshold
// is: the matcher seam's default is the learned model, and ranking a proposal
// decides nothing.
//
// DynamicScopes is empty: this service does not know which of
// the tenant's segments hand out addresses, and the safe answer to "we do not
// know" is the empty set, which lets ip_address vote. Narrowing it belongs with
// the segment's own dynamic flag, which is a later workstream.
func (s *DeviceService) identityEngine() (*identity.Engine, error) {
	s.identityOnce.Do(func() {
		s.identityRepo = pgidentity.New(s.db)
		s.identityEng, s.identityErr = identity.New(identity.Config{AdmissionEnabled: identity.AvailableCapabilities().Admission, Repo: s.identityRepo})
	})
	return s.identityEng, s.identityErr
}

// resolveObservation runs one observation through the engine inside ONE
// transaction, so the asset, its identifiers, its last-seen and its history
// rows land together or not at all.
//
// The retry mirrors inventory-service's: the engine resolves identifier
// ownership before it writes, and between that read and the write another
// intake of the same host can claim the same identifier. Resolving again sees
// the row the racing writer committed and MATCHES it, which is the outcome that
// was true all along. Once, not in a loop — a second conflict is a different
// fact (a store that has lost the invariant) and retrying forever would hide it.
// `after` runs on the ENGINE'S transaction once the resolution is known, so the
// management row, the credentials and the declared facts land with the identity
// rows or not at all. One observation is one fact about the world; splitting it
// across two transactions leaves an asset whose history says it was created and
// whose management configuration is absent, and no later run repairs that — the
// next observation MATCHES the asset that exists and never takes the create path
// again.
//
// A resolution that wrote nothing — the floor's contested path, where every
// identifier belongs to some other asset — hands `after` a ZERO ref. The
// callback is still run, and must check [identity.AssetRef.Zero] before writing
// anything about "the" asset.
func (s *DeviceService) resolveObservation(
	ctx context.Context,
	obs identity.Observation,
	after func(r *pgidentity.Repository, res identity.Resolution) error,
) (identity.Resolution, error) {
	engine, err := s.identityEngine()
	if err != nil {
		return identity.Resolution{}, fmt.Errorf("identification engine unavailable: %w", err)
	}
	var res identity.Resolution
	run := func() error {
		return s.identityRepo.RunInTx(ctx, obs.TenantID, func(r *pgidentity.Repository) error {
			// The tenant's auto-accept threshold, read in THIS transaction.
			//
			// Per observation and uncached, for the reasons on
			// identitysettings.ReadAutoAcceptThreshold: a cache would make a
			// tenant turning auto-merge off take effect "soon", and "a config
			// change that silently did not take effect" is a failure this
			// codebase has hit repeatedly.
			//
			// A failure to READ is returned, not swallowed into the default: a
			// threshold the database would not give us is not evidence the
			// tenant set zero, and the observation is better refused and
			// retried than resolved under a setting nobody chose. (A tenant who
			// has simply never set one DOES get zero — that is the reader's
			// answer, not an error.)
			threshold, tErr := identitysettings.ReadAutoAcceptThresholdFor(ctx, r.Tx(), obs.TenantID)
			if tErr != nil {
				return tErr
			}

			var rErr error
			res, rErr = engine.WithAutoAcceptThreshold(threshold).WithRepository(r).Resolve(ctx, obs)
			if rErr != nil {
				return rErr
			}
			if after == nil {
				return nil
			}
			return after(r, res)
		})
	}
	err = run()
	if errors.Is(err, identity.ErrIdentifierConflict) {
		log.Printf("[DeviceService] identity: %s raced another writer for an identifier; resolving again", observationLabel(obs))
		err = run()
	}
	if err != nil {
		return identity.Resolution{}, err
	}
	// AFTER the commit, and only for a merge the matcher made on the tenant's
	// behalf. An audit event announcing a merge that then rolled back would be a
	// record of something that did not happen — which is why this is here and
	// not inside the closure above.
	identityaudit.LogAutoAcceptedMerge(ctx, autoAcceptAuditLogger(), obs, res)
	return res, nil
}

// Repo exposes the identity repository so the interrogation paths in this
// package can write facts and relationships against the same asset tables
// without each opening their own.
func (s *DeviceService) Repo() (*pgidentity.Repository, error) {
	if _, err := s.identityEngine(); err != nil {
		return nil, err
	}
	return s.identityRepo, nil
}

func observationLabel(obs identity.Observation) string {
	if obs.DisplayName != "" {
		return obs.DisplayName
	}
	if len(obs.Identifiers) > 0 {
		return string(obs.Identifiers[0].Kind) + "=" + obs.Identifiers[0].Value
	}
	return "(no identifiers)"
}

func logDroppedIdentifier(in deviceObservationInput, r identity.RejectedIdentifier) {
	log.Printf("[DeviceService] identity: device %q dropped a %s identifier: %v",
		firstNonEmpty(in.Hostname, in.IPAddress, in.ManagementURL, in.DeviceType), r.Identifier.Kind, r.Err)
}

func logSegmentLookupFailed(tenantID uuid.UUID, err error) {
	log.Printf("[DeviceService] identity: segment lookup for tenant %s failed; hostname and IP identifiers will be recorded unscoped and will not decide a match: %v", tenantID, err)
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

	obs, err := s.deviceObservation(ctx, tenantID, deviceObservationInput{
		DeviceType:      req.DeviceType,
		Hostname:        derefStr(req.Hostname),
		IPAddress:       derefStr(req.IPAddress),
		ManagementURL:   derefStr(req.ManagementURL),
		SerialNumber:    derefStr(req.SerialNumber),
		CloudResourceID: cloudResourceIDFromMetadata(req.Metadata),
		DiscoveryMethod: discoveryMethod,
		Source:          declaredSource(),
		ObservedAt:      now,
	})
	if err != nil {
		return nil, err
	}

	fields := deviceFieldUpdate{
		DeviceType:            req.DeviceType,
		Hostname:              req.Hostname,
		IPAddress:             req.IPAddress,
		ManagementURL:         req.ManagementURL,
		Vendor:                req.Vendor,
		Model:                 req.Model,
		FirmwareVersion:       req.FirmwareVersion,
		TLSInsecureSkipVerify: req.TLSInsecureSkipVerify,
		CredentialID:          req.CredentialID,
		Username:              req.Username,
		Password:              req.Password,
		Metadata:              req.Metadata,
		Tags:                  req.Tags,
		DiscoveryMethod:       discoveryMethod,
		CreateManagement:      true,
	}

	var assetID uuid.UUID
	res, err := s.resolveObservation(ctx, obs, func(r *pgidentity.Repository, res identity.Resolution) error {
		if res.Asset.Zero() {
			// The floor's contested path: every identifier the operator gave us
			// belongs to some other asset, so nothing was created and there is
			// nothing to configure.
			//
			// nil, NOT an error. The engine wrote a merge proposal in THIS
			// transaction; returning an error rolls it back, and the message
			// the operator then reads tells them to go and review the thing
			// that was just erased. The outcome is mapped after the commit.
			return s.retainManagement(ctx, r, obs, res, fields)
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

	metaPatch := map[string]interface{}{}
	if strings.TrimSpace(in.DeviceType) != "" {
		metaPatch[deviceTypeKey] = strings.ToLower(strings.TrimSpace(in.DeviceType))
	}
	if len(in.Metadata) > 0 {
		metaPatch[deviceMetadataKey] = in.Metadata
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

	// A serial supplied on an UPDATE is a new identifier for an asset that
	// already exists, so it does not go through Resolve (which would be a
	// second observation of a thing we have already identified). Attaching it
	// directly is the same write Resolve would have made.
	if serial := strings.TrimSpace(derefStr(in.SerialNumber)); serial != "" {
		attachErr := r.AttachIdentifiers(ctx, ref, []identity.Identifier{{
			Kind:       identity.KindSerialNumber,
			Value:      serial,
			Confidence: 1,
			Source:     declaredSource(),
		}})
		if errors.Is(attachErr, identity.ErrIdentifierConflict) {
			// The serial belongs to a different asset. That is a merge question
			// for a human, not something to force: reported, not written.
			log.Printf("[DeviceService] serial %q already belongs to another asset in tenant %s; not attached", serial, tenantID)
		} else if attachErr != nil {
			return fmt.Errorf("failed to record device serial: %w", attachErr)
		}
	}
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
		TLSInsecureSkipVerify: req.TLSInsecureSkipVerify,
		ConnectionStatus:      req.ConnectionStatus,
		CredentialID:          req.CredentialID,
		Username:              req.Username,
		Password:              req.Password,
		Metadata:              req.Metadata,
		Tags:                  req.Tags,
	}

	// One transaction, same as create: the management row, the credentials, the
	// declared facts and the new address identifiers land together or not at
	// all. An edit that half-applied would leave the form and the database
	// disagreeing with no record of which.
	//
	// A new hostname or address is a new identifier for an asset we have ALREADY
	// identified, so it is attached rather than re-resolved — re-resolving would
	// be a second observation of a thing we have already named.
	if _, err := s.identityEngine(); err != nil {
		return nil, err
	}
	err = s.identityRepo.RunInTx(ctx, tenantID.String(), func(r *pgidentity.Repository) error {
		if applyErr := s.applyDeviceFields(ctx, r, tenantID, assetID, fields); applyErr != nil {
			return applyErr
		}
		return s.attachAddressIdentifiers(ctx, r, tenantID, assetID, derefStr(req.Hostname), derefStr(req.IPAddress))
	})
	if err != nil {
		return nil, err
	}

	return s.GetDevice(ctx, tenantID, assetID)
}

// attachAddressIdentifiers records a hostname or address an operator supplied
// on an existing asset.
//
// A value that already belongs to ANOTHER asset is reported and skipped, never
// forced: one identifier value maps to at most one asset, and overriding that
// here would be the merge the engine deliberately refuses to make on its own.
func (s *DeviceService) attachAddressIdentifiers(ctx context.Context, repo *pgidentity.Repository, tenantID, assetID uuid.UUID, hostname, ip string) error {
	if strings.TrimSpace(hostname) == "" && strings.TrimSpace(ip) == "" {
		return nil
	}
	segmentID, _ := s.segmentScope(ctx, tenantID, strings.TrimSpace(ip), strings.TrimSpace(hostname), "")
	ref := identity.AssetRef{TenantID: tenantID.String(), ID: assetID.String()}

	var ids []identity.Identifier
	if h := strings.TrimSpace(hostname); h != "" {
		kind, scope := identity.KindHostname, segmentID
		if strings.Contains(strings.TrimSuffix(h, "."), ".") {
			kind, scope = identity.KindFQDN, ""
		}
		ids = append(ids, identity.Identifier{Kind: kind, Value: h, Scope: scope, Confidence: 1, Source: declaredSource()})
	}
	if a := strings.TrimSpace(ip); a != "" {
		ids = append(ids, identity.Identifier{Kind: identity.KindIPAddress, Value: a, Scope: segmentID, Confidence: 1, Source: declaredSource()})
	}

	for _, id := range ids {
		normalized, normErr := id.Normalized()
		if normErr != nil {
			log.Printf("[DeviceService] identity: not attaching %s=%q: %v", id.Kind, id.Value, normErr)
			continue
		}
		attachErr := repo.AttachIdentifiers(ctx, ref, []identity.Identifier{normalized})
		if errors.Is(attachErr, identity.ErrIdentifierConflict) {
			log.Printf("[DeviceService] identity: %s=%q already belongs to another asset in tenant %s; not attached",
				normalized.Kind, normalized.Value, tenantID)
			continue
		}
		if attachErr != nil {
			return fmt.Errorf("failed to record device %s: %w", normalized.Kind, attachErr)
		}
	}
	return nil
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

	repo, err := s.Repo()
	if err != nil {
		return err
	}
	if histErr := repo.RecordHistory(ctx, identity.HistoryEntry{
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

// ResetSSHHostKeyPin clears the SSH host key pinned to a managed asset, so the
// next interrogation enrols the key the device presents (H7).
//
// The operator-facing half of fail-closed host-key verification: a device that
// was legitimately replaced or rekeyed has to be able to come back without
// anybody disabling the check.
func (s *DeviceService) ResetSSHHostKeyPin(ctx context.Context, tenantID, assetID uuid.UUID) error {
	return clearSSHHostKeyPin(ctx, s.db, tenantID, assetID)
}
