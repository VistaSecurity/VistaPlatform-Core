package processor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/events"
)

// The path a NATS job names is confined to <upload root>/<tenant>/. A refused
// path is neither opened nor deleted.

// bystander is a file outside the upload tree that a hostile job names; it
// must still exist, byte for byte, after the job is refused.
func bystander(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "do-not-delete.txt")
	if err := os.WriteFile(path, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func requireIntact(t *testing.T, path string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "precious" {
		t.Fatalf("%s was deleted or modified by a refused job (err=%v, content=%q)", path, err, got)
	}
}

func TestResolveUploadPath(t *testing.T) {
	root := t.TempDir()
	tenant, other := uuid.New(), uuid.New()
	mk := func(id uuid.UUID, name string) string {
		dir := filepath.Join(root, id.String())
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	own := mk(tenant, "a.pcap")
	foreign := mk(other, "b.pcap")
	outside := bystander(t)

	// A symlink inside the tenant's directory that leads out of it, and one
	// that stays inside.
	escape := filepath.Join(root, tenant.String(), "escape.pcap")
	if err := os.Symlink(outside, escape); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(root, tenant.String(), "inside.pcap")
	if err := os.Symlink(own, inside); err != nil {
		t.Fatal(err)
	}
	rootResolved, _ := filepath.EvalSymlinks(root)
	ownResolved := filepath.Join(rootResolved, tenant.String(), "a.pcap")

	for _, tc := range []struct {
		name string
		path string
		ok   bool
		want string // expected returned path when ok
	}{
		{"own upload", own, true, ownResolved},
		{"not yet on disk", filepath.Join(root, tenant.String(), "pending.pcap"), true, filepath.Join(root, tenant.String(), "pending.pcap")},
		{"symlink staying inside", inside, true, ownResolved},
		{"dot-dot escape", filepath.Join(root, tenant.String(), "..", "..", "etc", "passwd"), false, ""},
		{"dot-dot to the traversal target", "/tmp/pcap-uploads/../../etc/passwd", false, ""},
		{"traversal relative", "../../etc/passwd", false, ""},
		{"absolute outside the root", "/etc/passwd", false, ""},
		{"a file elsewhere on disk", outside, false, ""},
		{"another tenant's capture", foreign, false, ""},
		{"the tenant directory itself", filepath.Join(root, tenant.String()), false, ""},
		{"the root itself", root, false, ""},
		{"sibling directory sharing the prefix", filepath.Join(root, tenant.String()+"-evil", "a.pcap"), false, ""},
		{"symlink leading out", escape, false, ""},
		{"empty", "", false, ""},
		{"NUL byte", own + "\x00.pcap", false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveUploadPath(root, tenant, tc.path)
			if tc.ok {
				if err != nil {
					t.Fatalf("refused a legitimate path: %v", err)
				}
				if got != tc.want {
					t.Fatalf("resolved to %q, want %q", got, tc.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted %q, resolved to %q", tc.path, got)
			}
			if !errors.Is(err, errPathOutsideUploadRoot) {
				t.Fatalf("err = %v, want errPathOutsideUploadRoot", err)
			}
		})
	}

	t.Run("unconfigured root", func(t *testing.T) {
		if _, err := resolveUploadPath("", tenant, own); err == nil {
			t.Fatal("an empty upload root accepted a path")
		}
	})

	t.Run("a FIFO is not a capture", func(t *testing.T) {
		fifo := filepath.Join(root, tenant.String(), "pipe.pcap")
		if err := mkfifo(fifo); err != nil {
			t.Skipf("no mkfifo here: %v", err)
		}
		if _, err := resolveUploadPath(root, tenant, fifo); err == nil {
			t.Fatal("accepted a FIFO")
		}
	})
}

// Through HandlePcapJob (the real entry point): a message naming a file outside
// the tenant's directory is refused as a permanent failure, audited, and the
// named file is left alone. Mutation: delete the resolveUploadPath call and the
// file is removed.
func TestHandlePcapJob_RefusesAPathOutsideTheUploadRoot(t *testing.T) {
	sink := &recordingSink{}
	p := newTestProcessor(t, sink)
	tenantID := uuid.New()

	// Another tenant's capture: a valid pcap, in the right root, wrong tenant.
	otherTenant := uuid.New()
	foreignCapture := writeEmptyPcap(t, p, otherTenant)
	foreignBefore, err := os.ReadFile(foreignCapture)
	if err != nil {
		t.Fatal(err)
	}

	victim := bystander(t)
	for name, path := range map[string]string{
		"relative traversal":       "../../etc/passwd",
		"absolute traversal":       filepath.Join(p.cfg.TempDir, tenantID.String(), "..", "..", "etc", "passwd"),
		"absolute path elsewhere":  victim,
		"another tenant's capture": foreignCapture,
	} {
		t.Run(name, func(t *testing.T) {
			before := len(sink.all())
			job := events.NewPcapJobEvent(tenantID, uuid.New(), path, "x.pcap", 1)
			err := p.HandlePcapJob(context.Background(), jobMsg(t, job))
			if err == nil {
				t.Fatal("a job outside the upload root was processed")
			}
			if !events.IsPermanent(err) {
				t.Errorf("not permanent, so a redelivery would repeat it: %v", err)
			}
			if !errors.Is(err, errPathOutsideUploadRoot) {
				t.Errorf("err = %v, want errPathOutsideUploadRoot", err)
			}
			evts := sink.all()
			if len(evts) != before+1 || evts[len(evts)-1].ErrorKind != "path_rejected" {
				t.Errorf("the refusal was not audited as path_rejected: %#v", evts)
			}
		})
	}
	requireIntact(t, victim)
	if got, err := os.ReadFile(foreignCapture); err != nil || string(got) != string(foreignBefore) {
		t.Fatalf("another tenant's capture was deleted or changed by a refused job (err=%v)", err)
	}
}

// A symlink planted in the tenant's directory must not turn the processor's
// delete into a delete of its target.
func TestHandlePcapJob_SymlinkOutOfTheTenantDirectoryIsNotFollowed(t *testing.T) {
	p := newTestProcessor(t, &recordingSink{})
	tenantID := uuid.New()
	victim := bystander(t)

	link := uploadPathFor(p, tenantID, "planted.pcap")
	if err := os.MkdirAll(filepath.Dir(link), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}

	job := events.NewPcapJobEvent(tenantID, uuid.New(), link, "planted.pcap", 1)
	if err := p.HandlePcapJob(context.Background(), jobMsg(t, job)); err == nil {
		t.Fatal("a symlink out of the tenant directory was processed")
	}
	requireIntact(t, victim)
}

// The ordinary case still works end to end, and the capture is removed after
// it is processed.
func TestHandlePcapJob_ProcessesAndRemovesAnUploadInsideTheRoot(t *testing.T) {
	p := newTestProcessor(t, &recordingSink{})
	tenantID := uuid.New()
	path := writeEmptyPcap(t, p, tenantID)

	job := events.NewPcapJobEvent(tenantID, uuid.New(), path, "capture.pcap", 24)
	if err := p.HandlePcapJob(context.Background(), jobMsg(t, job)); err != nil {
		t.Fatalf("HandlePcapJob: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("the processed capture was not removed (stat err=%v)", err)
	}
}
