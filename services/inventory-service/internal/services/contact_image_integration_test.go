package services

// DB-integration tests for contacts and image attachments (DCIM BUILD_PLAN row
// 2.8). Skipped unless TEST_DATABASE_URL is set; run with make
// test-integration-db. The services run on the NON-OWNER app role, so RLS is
// in force exactly as in production.

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"image"
	"image/png"
	"io"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func pngBytes(t *testing.T, w, h int) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := png.Encode(&b, image.NewRGBA(image.Rect(0, 0, w, h))); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func contactJSON(t *testing.T, m map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func roleID(t *testing.T, owner *sql.DB, slug string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := owner.QueryRow(`SELECT id FROM contact_roles WHERE tenant_id IS NULL AND slug = $1`, slug).Scan(&id); err != nil {
		t.Fatalf("platform contact role %q is not seeded: %v", slug, err)
	}
	return id
}

// RLS: tenant B sees none of tenant A's contacts or assignments, and cannot
// write a row for tenant A; the platform roles are readable by both and
// writable by neither.
//
// Mutation: drop contacts_tenant_isolation / contact_assignments_tenant_isolation
// (or the ENABLE ROW LEVEL SECURITY) → B lists A's rows; drop
// contact_roles_catalogue_read → the seeded roles are not listed.
func TestIntegration_Contacts_RLS(t *testing.T) {
	owner, app, tenantA := ifaceFixture(t)
	tenantB := testdb.NewTenant(t, owner)
	ctx := ifaceActorCtx()
	svc := NewContactService(app)
	asset := ifaceSeedAsset(t, owner, tenantA, "monitoring")

	c, err := svc.Create(ctx, tenantA, RouteContacts, contactJSON(t, map[string]any{"name": "NOC", "email": "noc@example.test"}))
	if err != nil {
		t.Fatalf("create contact: %v", err)
	}
	cid := catID(t, c)
	a, err := svc.AssignToObject(ctx, tenantA, dcim.ObjectKindAsset, asset, contactJSON(t, map[string]any{"contact_id": cid, "role_id": roleID(t, owner, "on-call"), "priority": "primary"}))
	if err != nil {
		t.Fatalf("assign: %v", err)
	}

	for _, route := range []string{RouteContacts, RouteContactAssignments} {
		rows, total, err := svc.List(ctx, tenantB, route, IPAMListParams{Limit: 50})
		if err != nil || total != 0 || len(rows) != 0 {
			t.Fatalf("tenant B listed %d/%d %s of tenant A (%v)", len(rows), total, route, err)
		}
	}
	if _, err := svc.Get(ctx, tenantB, RouteContacts, cid); !errors.Is(err, ErrIPAMNotFound) {
		t.Fatalf("tenant B got tenant A's contact: %v", err)
	}
	if _, err := svc.Get(ctx, tenantB, RouteContactAssignments, catID(t, a)); !errors.Is(err, ErrIPAMNotFound) {
		t.Fatalf("tenant B got tenant A's assignment: %v", err)
	}
	// B cannot assign A's contact (the contact is not visible to B).
	assetB := ifaceSeedAsset(t, owner, tenantB, "monitoring")
	if _, err := svc.AssignToObject(ctx, tenantB, dcim.ObjectKindAsset, assetB, contactJSON(t, map[string]any{"contact_id": cid, "role_id": roleID(t, owner, "owner")})); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("tenant B assigned tenant A's contact: %v", err)
	}
	// The WITH CHECK half: scoped to B, an insert for A is refused.
	testdb.AsTenant(t, owner, tenantB, func(tx *sql.Tx) {
		if _, err := tx.Exec(`INSERT INTO contacts (tenant_id, name) VALUES ($1, 'x')`, tenantA); err == nil {
			t.Error("WITH CHECK let tenant B insert a contact for tenant A")
		}
	})

	// Platform roles: readable, never writable.
	roles, _, err := svc.List(ctx, tenantB, RouteContactRoles, IPAMListParams{Limit: 50})
	if err != nil || len(roles) < 5 {
		t.Fatalf("platform contact roles not listed for a tenant: %d (%v)", len(roles), err)
	}
	if _, err := svc.Update(ctx, tenantA, RouteContactRoles, roleID(t, owner, "noc"), []byte(`{"name":"x"}`)); !errors.Is(err, ErrIPAMReadOnly) {
		t.Fatalf("a tenant edited a platform role: %v", err)
	}
	if err := svc.Delete(ctx, tenantA, RouteContactRoles, roleID(t, owner, "noc")); !errors.Is(err, ErrIPAMReadOnly) {
		t.Fatalf("a tenant deleted a platform role: %v", err)
	}
	// A tenant's own role in use cannot be deleted; unused can.
	own, err := svc.Create(ctx, tenantA, RouteContactRoles, []byte(`{"name":"Escalation"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AssignToObject(ctx, tenantA, dcim.ObjectKindAsset, asset, contactJSON(t, map[string]any{"contact_id": cid, "role_id": catID(t, own)})); err != nil {
		t.Fatal(err)
	}
	if err := svc.Delete(ctx, tenantA, RouteContactRoles, catID(t, own)); !errors.Is(err, ErrIPAMInUse) {
		t.Fatalf("a role in use was deleted: %v", err)
	}
}

// An assignment to an object that does not exist for the tenant is a 404:
// nonexistent id, another tenant's object, and a kind whose table does not
// exist. Duplicates are a conflict; deleting a contact removes its assignments.
//
// Mutation: remove the objectExists call in prepareContactAssignment → each
// "not found" case below creates a dangling row instead.
func TestIntegration_Contacts_AssignmentResolvesObject(t *testing.T) {
	owner, app, tenantA := ifaceFixture(t)
	tenantB := testdb.NewTenant(t, owner)
	ctx := ifaceActorCtx()
	svc := NewContactService(app)
	mine := ifaceSeedAsset(t, owner, tenantA, "monitoring")
	theirs := ifaceSeedAsset(t, owner, tenantB, "monitoring")
	c, _ := svc.Create(ctx, tenantA, RouteContacts, []byte(`{"name":"Alice"}`))
	cid := catID(t, c)
	body := func(role string) []byte {
		return contactJSON(t, map[string]any{"contact_id": cid, "role_id": roleID(t, owner, role)})
	}

	if _, err := svc.AssignToObject(ctx, tenantA, dcim.ObjectKindAsset, uuid.New(), body("owner")); !errors.Is(err, ErrIPAMNotFound) {
		t.Fatalf("nonexistent object: %v, want not found", err)
	}
	if _, err := svc.AssignToObject(ctx, tenantA, dcim.ObjectKindAsset, theirs, body("owner")); !errors.Is(err, ErrIPAMNotFound) {
		t.Fatalf("another tenant's object: %v, want not found", err)
	}
	// Through the generic route too (the path builds object_kind/object_id by hand).
	raw := contactJSON(t, map[string]any{"object_kind": "asset", "object_id": theirs.String(), "contact_id": cid, "role_id": roleID(t, owner, "owner")})
	if _, err := svc.Create(ctx, tenantA, RouteContactAssignments, raw); !errors.Is(err, ErrIPAMNotFound) {
		t.Fatalf("POST /contact-assignments at another tenant's object: %v", err)
	}
	if _, _, err := svc.ListForObject(ctx, tenantA, dcim.ObjectKindAsset, theirs, IPAMListParams{Limit: 10}); !errors.Is(err, ErrIPAMNotFound) {
		t.Fatalf("listing another tenant's object: %v", err)
	}
	if _, err := svc.AssignToObject(ctx, tenantA, dcim.ObjectKindAsset, mine, []byte(`{"object_id":"`+mine.String()+`","contact_id":"`+cid.String()+`","role_id":"`+roleID(t, owner, "owner").String()+`"}`)); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("a body naming the object must be refused: %v", err)
	}
	if _, err := svc.AssignToObject(ctx, tenantA, dcim.ObjectKindAsset, mine, body("owner")); err != nil {
		t.Fatalf("valid assignment: %v", err)
	}
	if _, err := svc.AssignToObject(ctx, tenantA, dcim.ObjectKindAsset, mine, body("owner")); !errors.Is(err, ErrIPAMConflict) {
		t.Fatalf("duplicate assignment: %v, want conflict", err)
	}
	if _, err := svc.AssignToObject(ctx, tenantA, dcim.ObjectKindAsset, mine, body("billing")); err != nil {
		t.Fatalf("same contact, another role: %v", err)
	}
	rows, total, err := svc.ListForObject(ctx, tenantA, dcim.ObjectKindAsset, mine, IPAMListParams{Limit: 10})
	if err != nil || total != 2 || len(rows) != 2 {
		t.Fatalf("list for object: %d/%d %v", len(rows), total, err)
	}
	var first struct {
		Contact struct{ Name string } `json:"contact"`
		Role    struct{ Slug string } `json:"role"`
	}
	_ = json.Unmarshal(rows[0], &first)
	if first.Contact.Name != "Alice" || first.Role.Slug == "" {
		t.Fatalf("contact and role are not inlined: %s", rows[0])
	}
	// A bad priority is a 400.
	bad := contactJSON(t, map[string]any{"contact_id": cid, "role_id": roleID(t, owner, "noc"), "priority": "urgent"})
	if _, err := svc.AssignToObject(ctx, tenantA, dcim.ObjectKindAsset, mine, bad); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("bad priority: %v", err)
	}
	// Deleting the contact removes its assignments.
	if err := svc.Delete(ctx, tenantA, RouteContacts, cid); err != nil {
		t.Fatal(err)
	}
	if _, total, _ := svc.ListForObject(ctx, tenantA, dcim.ObjectKindAsset, mine, IPAMListParams{Limit: 10}); total != 0 {
		t.Fatalf("assignments outlived their contact: %d", total)
	}
	// A contact cannot be its own group, nor cyclic.
	a, _ := svc.Create(ctx, tenantA, RouteContacts, []byte(`{"name":"Team"}`))
	b, _ := svc.Create(ctx, tenantA, RouteContacts, contactJSON(t, map[string]any{"name": "Member", "group_id": catID(t, a).String()}))
	if _, err := svc.Update(ctx, tenantA, RouteContacts, catID(t, a), contactJSON(t, map[string]any{"group_id": catID(t, b).String()})); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("contact group cycle: %v", err)
	}
	if _, err := svc.Create(ctx, tenantA, RouteContacts, []byte(`{"name":"Bad","email":"not an address"}`)); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("bad email: %v", err)
	}
}

// Images: stores and lists; rejects 6 MB and non-images; delete removes the
// stored bytes; a device type's slot follows the upload and the delete.
//
// Mutation: remove the size check in sniffImage → the 6 MB upload is stored;
// remove the type sniff (accept anything) → the .exe is stored; remove the
// blobs.Delete in ImageService.Delete → the bytes outlive the row.
func TestIntegration_Images_UploadListDelete(t *testing.T) {
	owner, app, tenantA := ifaceFixture(t)
	tenantB := testdb.NewTenant(t, owner)
	ctx := ifaceActorCtx()
	blobs := NewMemoryBlobStore()
	svc := NewImageService(app, blobs)
	asset := ifaceSeedAsset(t, owner, tenantA, "monitoring")
	up := func(data []byte, name string) (json.RawMessage, error) {
		return svc.Upload(ctx, tenantA, ImageUpload{Kind: dcim.ObjectKindAsset, ObjectID: asset, Filename: name, Data: data})
	}

	if _, err := up(append(pngBytes(t, 8, 8), make([]byte, 6<<20)...), "big.png"); !errors.Is(err, ErrImageTooLarge) {
		t.Fatalf("6 MB upload: %v, want too large", err)
	}
	if _, err := up([]byte("MZ\x90\x00\x03\x00\x00\x00 not an image"), "tool.exe"); !errors.Is(err, ErrImageUnsupported) {
		t.Fatalf(".exe upload: %v, want unsupported", err)
	}
	// Named .png but not a png.
	if _, err := up([]byte("MZ\x90\x00 pretending"), "photo.png"); !errors.Is(err, ErrImageUnsupported) {
		t.Fatalf("exe named .png: %v", err)
	}
	if _, err := up([]byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`), "x.svg"); !errors.Is(err, ErrImageUnsupported) {
		t.Fatalf("svg with script: %v", err)
	}
	if len(blobs.Blobs) != 0 {
		t.Fatalf("a refused upload left %d blobs", len(blobs.Blobs))
	}
	if _, err := svc.Upload(ctx, tenantA, ImageUpload{Kind: dcim.ObjectKindAsset, ObjectID: uuid.New(), Filename: "a.png", Data: pngBytes(t, 4, 4)}); !errors.Is(err, ErrIPAMNotFound) {
		t.Fatalf("upload to a nonexistent object: %v", err)
	}
	if len(blobs.Blobs) != 0 {
		t.Fatalf("an upload to a missing object left a blob")
	}

	raw, err := up(pngBytes(t, 40, 30), `C:\fakepath\R12 front.png`)
	if err != nil {
		t.Fatalf("upload png: %v", err)
	}
	var img struct {
		ID         uuid.UUID `json:"id"`
		Name       string    `json:"name"`
		Width      int       `json:"width"`
		Height     int       `json:"height"`
		Size       int64     `json:"size_bytes"`
		StorageRef string    `json:"storage_ref"`
	}
	if err := json.Unmarshal(raw, &img); err != nil {
		t.Fatal(err)
	}
	if img.Width != 40 || img.Height != 30 || img.Name != "R12 front.png" || img.Size == 0 {
		t.Fatalf("metadata not recorded: %+v", img)
	}
	svgRaw, err := up([]byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 100"></svg>`), "plan.svg")
	if err != nil {
		t.Fatalf("upload svg: %v", err)
	}
	if !strings.Contains(string(svgRaw), `"width": 200`) && !strings.Contains(string(svgRaw), `"width":200`) {
		t.Fatalf("svg size not read from the viewBox: %s", svgRaw)
	}

	rows, total, err := svc.ListForObject(ctx, tenantA, dcim.ObjectKindAsset, asset, IPAMListParams{Limit: 10})
	if err != nil || total != 2 || len(rows) != 2 {
		t.Fatalf("list: %d/%d %v", len(rows), total, err)
	}
	if _, _, err := svc.ListForObject(ctx, tenantB, dcim.ObjectKindAsset, asset, IPAMListParams{Limit: 10}); !errors.Is(err, ErrIPAMNotFound) {
		t.Fatalf("tenant B listed tenant A's object's images: %v", err)
	}
	if _, err := svc.Get(ctx, tenantB, img.ID); !errors.Is(err, ErrIPAMNotFound) {
		t.Fatalf("tenant B read tenant A's image: %v", err)
	}
	rc, ct, _, err := svc.Download(ctx, tenantA, img.ID)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(rc)
	_ = rc.Close()
	if ct != "image/png" || !bytes.HasPrefix(got, []byte("\x89PNG")) {
		t.Fatalf("download: %s %d bytes", ct, len(got))
	}

	if err := svc.Delete(ctx, tenantA, img.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := blobs.Blobs[img.StorageRef]; ok {
		t.Fatal("the image's bytes outlived its row")
	}
	if _, err := svc.Get(ctx, tenantA, img.ID); !errors.Is(err, ErrIPAMNotFound) {
		t.Fatalf("deleted image still readable: %v", err)
	}
	var n int
	if err := owner.QueryRow(`SELECT count(*) FROM object_changes WHERE tenant_id = $1 AND object_kind = 'image_attachment'`, tenantA).Scan(&n); err != nil || n < 3 {
		t.Fatalf("image changes recorded: %d (%v), want create x2 + delete", n, err)
	}
}

// A device type's front/rear image: the upload sets the ref, a second upload
// replaces it (the first attachment is dropped), deleting clears it.
func TestIntegration_Images_DeviceTypeSlots(t *testing.T) {
	owner, app, tenant := ifaceFixture(t)
	ctx := ifaceActorCtx()
	cat := NewCatalogueService(app)
	blobs := NewMemoryBlobStore()
	svc := NewImageService(app, blobs)

	m, err := cat.Create(ctx, tenant, "manufacturers", []byte(`{"name":"Cisco"}`))
	if err != nil {
		t.Fatal(err)
	}
	dt, err := cat.Create(ctx, tenant, "device-types", []byte(`{"manufacturer_id":"`+catID(t, m).String()+`","model":"C9300-48P"}`))
	if err != nil {
		t.Fatal(err)
	}
	dtID := catID(t, dt)
	ref := func(col string) *string {
		var s sql.NullString
		if err := owner.QueryRow(`SELECT `+col+` FROM device_types WHERE id = $1`, dtID).Scan(&s); err != nil {
			t.Fatal(err)
		}
		if !s.Valid {
			return nil
		}
		return &s.String
	}
	upload := func(slot string) uuid.UUID {
		raw, err := svc.Upload(ctx, tenant, ImageUpload{Kind: dcim.ObjectKindDeviceType, ObjectID: dtID, Filename: "f.png", Slot: slot, Data: pngBytes(t, 10, 5)})
		if err != nil {
			t.Fatalf("upload %q: %v", slot, err)
		}
		return catID(t, raw)
	}
	first := upload("front")
	if r := ref("front_image_ref"); r == nil || blobs.Blobs[*r] == nil {
		t.Fatalf("front_image_ref not set to the stored image: %v", r)
	}
	if ref("rear_image_ref") != nil {
		t.Fatal("rear_image_ref set by a front upload")
	}
	second := upload("front")
	if _, err := svc.Get(ctx, tenant, first); !errors.Is(err, ErrIPAMNotFound) {
		t.Fatalf("the replaced front image was not dropped: %v", err)
	}
	if len(blobs.Blobs) != 1 {
		t.Fatalf("%d blobs after a replace, want 1", len(blobs.Blobs))
	}
	if err := svc.Delete(ctx, tenant, second); err != nil {
		t.Fatal(err)
	}
	if ref("front_image_ref") != nil {
		t.Fatal("front_image_ref still points at a deleted image")
	}
	if _, err := svc.Upload(ctx, tenant, ImageUpload{Kind: dcim.ObjectKindDeviceType, ObjectID: dtID, Filename: "f.png", Slot: "side", Data: pngBytes(t, 4, 4)}); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("bad slot: %v", err)
	}
	a := ifaceSeedAsset(t, owner, tenant, "monitoring")
	if _, err := svc.Upload(ctx, tenant, ImageUpload{Kind: dcim.ObjectKindAsset, ObjectID: a, Filename: "f.png", Slot: "front", Data: pngBytes(t, 4, 4)}); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("slot on a non-device-type: %v", err)
	}
}
