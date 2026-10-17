package services

// ImageService owns image attachments (DCIM BUILD_PLAN row 2.8; DATA_MODEL §8
// image_attachments): an image hung on any object, bytes in ImageBlobStore,
// metadata (and the change record) in Postgres.
//
// A device type's front and rear image are image attachments too: uploading
// with slot=front|rear also points device_types.front_image_ref /
// rear_image_ref at the attachment's storage_ref (and replaces the previous
// one), which is how the rack elevation (row 2.5) finds the picture.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
)

// ImageSlots are the device type image slots.
var ImageSlots = []string{"front", "rear"}

func imageSpecs() []*ipamSpec {
	return []*ipamSpec{{
		Kind: dcim.ObjectKindImageAttachment, Table: "image_attachments", Route: "images",
		Cols: []ipamCol{
			{Name: "object_kind", Type: colText, Required: true},
			{Name: "object_id", Type: colUUID, Required: true},
			{Name: "storage_ref", Type: colText, Required: true},
			{Name: "name", Type: colText},
			{Name: "width", Type: colInt, Required: true},
			{Name: "height", Type: colInt, Required: true},
			{Name: "size_bytes", Type: colBigint, Required: true},
			{Name: "description", Type: colText},
			{Name: "custom_fields", Type: colJSON},
			{Name: "source_kind", Type: colText},
			{Name: "source_ref", Type: colText},
		},
		Filters: []ipamFilter{
			{Param: "object_kind", Column: "object_kind", Type: colText},
			{Param: "object_id", Column: "object_id", Type: colUUID},
			{Param: "storage_ref", Column: "storage_ref", Type: colText},
		},
		Order: "t.created_at DESC, t.id",
	}}
}

// ImageService is the image attachment store.
type ImageService struct {
	db    *sql.DB
	eng   *IPAMService
	blobs ImageBlobStore
	dtype *ipamSpec
}

// NewImageService returns the store over db and blobs.
func NewImageService(db *sql.DB, blobs ImageBlobStore) *ImageService {
	s := &ImageService{db: db, eng: newObjectEngine(db, imageSpecs()), blobs: blobs}
	for _, sp := range catalogueSpecs() {
		if sp.Route == "device-types" {
			s.dtype = sp
		}
	}
	return s
}

// ImageUpload is one upload request.
type ImageUpload struct {
	Kind        dcim.ObjectKind
	ObjectID    uuid.UUID
	Filename    string // as the client named it; shown as the attachment's name
	Description string
	Slot        string // "front" / "rear" for a device type, else ""
	Data        []byte
}

func (s *ImageService) guard(ctx context.Context, tenant uuid.UUID, kind dcim.ObjectKind, id uuid.UUID) error {
	return s.eng.tx(ctx, tenant, func(tx *sql.Tx) error {
		if err := objectExists(ctx, tx, tenant, kind, id); err != nil {
			if errors.Is(err, ErrDcimObjectNotFound) {
				return ErrIPAMNotFound
			}
			return err
		}
		return nil
	})
}

// ListForObject lists an object's images, newest first.
func (s *ImageService) ListForObject(ctx context.Context, tenant uuid.UUID, kind dcim.ObjectKind, id uuid.UUID, p IPAMListParams) ([]json.RawMessage, int, error) {
	if err := s.guard(ctx, tenant, kind, id); err != nil {
		return nil, 0, err
	}
	if p.Filters == nil {
		p.Filters = map[string]string{}
	}
	p.Filters["object_kind"] = string(kind)
	p.Filters["object_id"] = id.String()
	return s.eng.List(ctx, tenant, "images", p)
}

// List lists images across objects (filters: object_kind, object_id, storage_ref).
func (s *ImageService) List(ctx context.Context, tenant uuid.UUID, p IPAMListParams) ([]json.RawMessage, int, error) {
	return s.eng.List(ctx, tenant, "images", p)
}

// Get returns one image's metadata.
func (s *ImageService) Get(ctx context.Context, tenant uuid.UUID, id uuid.UUID) (json.RawMessage, error) {
	return s.eng.Get(ctx, tenant, "images", id)
}

// Upload validates, stores and records one image.
func (s *ImageService) Upload(ctx context.Context, tenant uuid.UUID, in ImageUpload) (json.RawMessage, error) {
	info, err := sniffImage(in.Data)
	if err != nil {
		return nil, err
	}
	if in.Slot != "" {
		if in.Kind != dcim.ObjectKindDeviceType {
			return nil, ipamInvalid("slot applies only to a device type")
		}
		if in.Slot != "front" && in.Slot != "rear" {
			return nil, ipamInvalid("slot must be front or rear")
		}
	}
	if err := s.guard(ctx, tenant, in.Kind, in.ObjectID); err != nil {
		return nil, err
	}
	filename := uuid.NewString() + info.Ext
	ref, err := s.blobs.Put(ctx, tenant, filename, info.ContentType, in.Data)
	if err != nil {
		return nil, err
	}
	name := cleanImageName(in.Filename)
	row := map[string]any{
		"object_kind": string(in.Kind),
		"object_id":   in.ObjectID.String(),
		"storage_ref": ref,
		"name":        name,
		"width":       int64(info.Width),
		"height":      int64(info.Height),
		"size_bytes":  int64(len(in.Data)),
	}
	if strings.TrimSpace(in.Description) != "" {
		row["description"] = strings.TrimSpace(in.Description)
	}
	var out json.RawMessage
	var replaced []string
	err = s.eng.tx(ctx, tenant, func(tx *sql.Tx) error {
		post, err := s.eng.createTx(ctx, tx, s.eng.specs["images"], tenant, row, "")
		if err != nil {
			return err
		}
		if in.Slot != "" {
			replaced, err = s.pointDeviceType(ctx, tx, tenant, in.ObjectID, in.Slot, &ref)
			if err != nil {
				return err
			}
		}
		out, err = json.Marshal(post)
		return err
	})
	if err != nil {
		_ = s.blobs.Delete(ctx, tenant, ref)
		return nil, mapIPAMError(err, false)
	}
	// The replaced front/rear attachment is superseded: drop it.
	for _, old := range replaced {
		_ = s.deleteByRef(ctx, tenant, old)
	}
	return out, nil
}

// pointDeviceType sets (or, with ref nil, clears) the device type's slot ref
// and returns the previous ref if there was one. Recorded as a change on the
// device type.
func (s *ImageService) pointDeviceType(ctx context.Context, tx *sql.Tx, tenant, id uuid.UUID, slot string, ref *string) ([]string, error) {
	col := slot + "_image_ref"
	pre, err := getRow(ctx, tx, s.dtype, id, true)
	if err != nil {
		return nil, err
	}
	var prev []string
	if p, ok := pre[col].(string); ok && p != "" {
		prev = append(prev, p)
	}
	var arg any
	if ref != nil {
		arg = *ref
	}
	var raw []byte
	q := fmt.Sprintf(`UPDATE public.device_types AS t SET %s = $3, updated_at = now() WHERE t.tenant_id = $1 AND t.id = $2 RETURNING to_jsonb(t)`, col)
	if err := tx.QueryRowContext(ctx, q, tenant, id, arg).Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrIPAMNotFound
		}
		return nil, err
	}
	post, err := decodeRow(s.dtype, raw)
	if err != nil {
		return nil, err
	}
	if err := recordIPAMChange(ctx, tx, s.dtype, tenant, changes.ActionUpdate, pre, post, ""); err != nil {
		return nil, err
	}
	if ref != nil && len(prev) == 1 && prev[0] == *ref {
		prev = nil
	}
	return prev, nil
}

// Delete removes one image: its row (recorded), any device type slot pointing
// at it, then its bytes.
func (s *ImageService) Delete(ctx context.Context, tenant, id uuid.UUID) error {
	var ref string
	err := s.eng.tx(ctx, tenant, func(tx *sql.Tx) error {
		pre, err := getRow(ctx, tx, s.eng.specs["images"], id, true)
		if err != nil {
			return err
		}
		ref, _ = pre["storage_ref"].(string)
		if fmt.Sprint(pre["object_kind"]) == string(dcim.ObjectKindDeviceType) {
			dt, err := uuid.Parse(fmt.Sprint(pre["object_id"]))
			if err != nil {
				return err
			}
			cur, err := getRow(ctx, tx, s.dtype, dt, false)
			if err == nil {
				for _, slot := range ImageSlots {
					if r, _ := cur[slot+"_image_ref"].(string); r != "" && r == ref {
						if _, err := s.pointDeviceType(ctx, tx, tenant, dt, slot, nil); err != nil {
							return err
						}
					}
				}
			} else if !errors.Is(err, ErrIPAMNotFound) {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM public.image_attachments WHERE tenant_id = $1 AND id = $2`, tenant, id); err != nil {
			return err
		}
		return recordIPAMChange(ctx, tx, s.eng.specs["images"], tenant, changes.ActionDelete, pre, nil, "")
	})
	if err != nil {
		return mapIPAMError(err, true)
	}
	if err := s.blobs.Delete(ctx, tenant, ref); err != nil {
		return fmt.Errorf("image row removed but its bytes could not be: %w", err)
	}
	return nil
}

// deleteByRef drops the attachment whose bytes live at ref (best effort).
func (s *ImageService) deleteByRef(ctx context.Context, tenant uuid.UUID, ref string) error {
	rows, _, err := s.eng.List(ctx, tenant, "images", IPAMListParams{Filters: map[string]string{"storage_ref": ref}, Limit: 1})
	if err != nil || len(rows) == 0 {
		return err
	}
	var r struct {
		ID uuid.UUID `json:"id"`
	}
	if err := json.Unmarshal(rows[0], &r); err != nil {
		return err
	}
	return s.Delete(ctx, tenant, r.ID)
}

// Download opens an image's bytes and reports its content type.
func (s *ImageService) Download(ctx context.Context, tenant, id uuid.UUID) (io.ReadCloser, string, string, error) {
	raw, err := s.Get(ctx, tenant, id)
	if err != nil {
		return nil, "", "", err
	}
	var r struct {
		Ref  string  `json:"storage_ref"`
		Name *string `json:"name"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, "", "", err
	}
	rc, err := s.blobs.Open(ctx, tenant, r.Ref)
	if err != nil {
		return nil, "", "", err
	}
	name := ""
	if r.Name != nil {
		name = *r.Name
	}
	return rc, contentTypeOfRef(r.Ref), name, nil
}

func contentTypeOfRef(ref string) string {
	switch strings.ToLower(path.Ext(ref)) {
	case ".png":
		return "image/png"
	case ".jpg":
		return "image/jpeg"
	case ".webp":
		return "image/webp"
	case ".svg":
		return "image/svg+xml"
	}
	return "application/octet-stream"
}

func cleanImageName(n string) any {
	n = strings.TrimSpace(path.Base(strings.ReplaceAll(n, "\\", "/")))
	if n == "." || n == "/" || n == "" {
		return nil
	}
	if len(n) > 200 {
		n = n[:200]
	}
	return n
}

// ImageObjects describes the image route for the contract tests.
func ImageObjects() []IPAMObjectInfo {
	sp := imageSpecs()[0]
	info := IPAMObjectInfo{Route: sp.Route, Table: sp.Table, Kind: string(sp.Kind)}
	for _, c := range sp.Cols {
		info.Writable = append(info.Writable, c.Name)
		if c.Required {
			info.Required = append(info.Required, c.Name)
		}
	}
	return []IPAMObjectInfo{info}
}
