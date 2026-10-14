package backups

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type backupsRecordingAuditor struct {
	mu     sync.Mutex
	events []AuditEvent
}

func (a *backupsRecordingAuditor) Record(_ *gin.Context, ev AuditEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, ev)
}

func (a *backupsRecordingAuditor) last() AuditEvent {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.events) == 0 {
		return AuditEvent{}
	}
	return a.events[len(a.events)-1]
}

func backupsEngine(h *Handlers) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/backups", h.List)
	r.POST("/backups", h.Create)
	r.GET("/backups/:id/download", h.Download)
	r.DELETE("/backups/:id", h.Delete)
	return r
}

func backupsDo(r http.Handler, method, path, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	return w
}

func errCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var e struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &e)
	return e.Error
}

func TestHandlers_CreateStatusCodes(t *testing.T) {
	bh := newBackupsHarness(t, 5)
	aud := &backupsRecordingAuditor{}
	bh.h.auditor = aud
	r := backupsEngine(bh.h)

	for body, want := range map[string]string{
		`{"include_secrets":true}`:                                  "passphrase_required",
		`{"include_secrets":true,"passphrase":"short"}`:             "passphrase_too_short",
		`{"include_secrets":false,"passphrase":"no secrets here!"}`: "passphrase_without_secrets",
		`{"include_secrets":"yes"}`:                                 "invalid_request",
	} {
		if w := backupsDo(r, http.MethodPost, "/backups", body); w.Code != http.StatusBadRequest || errCode(t, w) != want {
			t.Errorf("%s: %d %s, want 400 %s", body, w.Code, w.Body.String(), want)
		}
	}
	w := backupsDo(r, http.MethodPost, "/backups", `{}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var created CreateResponse
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	if created.Backup.Status != StatusRunning || created.Run.Kind != "backup" {
		t.Fatalf("created %+v", created)
	}
	if ev := aud.last(); ev.EventType != EventBackupCreated || !ev.Success || ev.ResourceID != created.Backup.ID.String() {
		t.Fatalf("audit %+v", ev)
	}
	if w := backupsDo(r, http.MethodPost, "/backups", `{}`); w.Code != http.StatusConflict || errCode(t, w) != "run_in_progress" {
		t.Fatalf("second create: %d %s", w.Code, w.Body.String())
	}
	if w := backupsDo(r, http.MethodDelete, "/backups/"+created.Backup.ID.String(), ""); w.Code != http.StatusConflict {
		t.Fatalf("delete running: %d", w.Code)
	}

	unavailable := NewHandlers(NewService(Config{}, nil, nil, nil, nil), nil, nil)
	if w := backupsDo(backupsEngine(unavailable), http.MethodPost, "/backups", `{}`); w.Code != http.StatusServiceUnavailable || errCode(t, w) != "backups_unavailable" {
		t.Fatalf("unavailable: %d %s", w.Code, w.Body.String())
	}
	if w := backupsDo(backupsEngine(unavailable), http.MethodGet, "/backups", ""); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"available":false`) {
		t.Fatalf("unavailable list: %d %s", w.Code, w.Body.String())
	}
}

// readyBackup puts a ready backup of the given size on the volume.
func (bh *backupsHarness) readyBackup(size int, encrypted bool) Backup {
	t := bh.t
	t.Helper()
	b := Backup{ID: uuid.New(), CreatedAt: time.Date(2026, 10, 14, 3, 12, 0, 0, time.UTC), Contents: Contents{Database: true, Secrets: encrypted},
		Encrypted: encrypted, Status: StatusReady, Manifest: &Manifest{AppVersion: "4.6.0"}}
	name := FileBundleTar
	if encrypted {
		name = FileBundleEnc
	}
	b.FilePath = filepath.Join(b.ID.String(), name)
	n := int64(size)
	b.SizeBytes = &n
	_ = os.MkdirAll(filepath.Join(bh.root, b.ID.String()), 0o700)
	mustWrite(t, filepath.Join(bh.root, b.FilePath), bytes.Repeat([]byte("b"), size))
	_ = bh.store.Insert(context.Background(), b)
	return b
}

func TestHandlers_DownloadHeadersAuditAndDelete(t *testing.T) {
	bh := newBackupsHarness(t, 5)
	aud := &backupsRecordingAuditor{}
	bh.h.auditor = aud
	r := backupsEngine(bh.h)
	b := bh.readyBackup(5000, true)

	w := backupsDo(r, http.MethodGet, "/backups/"+b.ID.String()+"/download", "")
	if w.Code != http.StatusOK || w.Body.Len() != 5000 {
		t.Fatalf("download: %d, %d bytes", w.Code, w.Body.Len())
	}
	if got := w.Header().Get("Content-Length"); got != "5000" {
		t.Fatalf("Content-Length %q", got)
	}
	if got := w.Header().Get("Content-Disposition"); got != `attachment; filename="vista-platform-backup-20261014-031200-4.6.0.enc"` {
		t.Fatalf("Content-Disposition %q", got)
	}
	if ev := aud.last(); ev.EventType != EventBackupDownloaded || ev.EventCategory != "data" || !ev.Success || ev.Metadata["bytes"] != int64(5000) {
		t.Fatalf("download audit %+v", ev)
	}

	if w := backupsDo(r, http.MethodGet, "/backups/not-a-uuid/download", ""); w.Code != http.StatusNotFound {
		t.Fatalf("bad id: %d", w.Code)
	}
	if w := backupsDo(r, http.MethodGet, "/backups/"+uuid.NewString()+"/download", ""); w.Code != http.StatusNotFound {
		t.Fatalf("missing: %d", w.Code)
	}

	if w := backupsDo(r, http.MethodDelete, "/backups/"+b.ID.String(), ""); w.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
	if ev := aud.last(); ev.EventType != EventBackupDeleted || !ev.Success {
		t.Fatalf("delete audit %+v", ev)
	}
	if _, err := os.Stat(filepath.Join(bh.root, b.ID.String())); err == nil {
		t.Fatal("delete left the files")
	}
	if w := backupsDo(r, http.MethodGet, "/backups/"+b.ID.String()+"/download", ""); w.Code != http.StatusConflict || errCode(t, w) != "not_ready" {
		t.Fatalf("download deleted: %d %s", w.Code, w.Body.String())
	}
	list := backupsDo(r, http.MethodGet, "/backups", "")
	if strings.Contains(list.Body.String(), b.ID.String()) {
		t.Fatal("a deleted backup is still listed")
	}
	if strings.Contains(list.Body.String(), "file_path") {
		t.Fatal("the list exposes file paths")
	}
}

// The API server's WriteTimeout bounds a WHOLE response (15s in
// shared/http). A multi-GB download takes longer than that, so the handler
// must keep extending the deadline per chunk. A slow client here takes ~4x the
// server's WriteTimeout and must still receive every byte.
func TestHandlers_DownloadOutlivesServerWriteTimeout(t *testing.T) {
	bh := newBackupsHarness(t, 5)
	bh.h.downloadIdle = 2 * time.Second
	size := 6 << 20
	b := bh.readyBackup(size, false)

	srv := httptest.NewUnstartedServer(backupsEngine(bh.h))
	srv.Config.WriteTimeout = 250 * time.Millisecond
	srv.Start()
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/backups/" + b.ID.String() + "/download")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var got int64
	buf := make([]byte, 1<<20)
	for {
		time.Sleep(160 * time.Millisecond) // a slow client
		n, rerr := io.ReadFull(resp.Body, buf)
		got += int64(n)
		if rerr != nil {
			break
		}
	}
	if got != int64(size) {
		t.Fatalf("received %d of %d bytes: the download was cut off by the server's WriteTimeout", got, size)
	}
}
