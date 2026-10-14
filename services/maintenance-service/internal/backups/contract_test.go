package backups

// Contract test: the REAL backup and run handlers, over httptest, answer
// bodies that conform to api/openapi/maintenance-service.openapi.yaml.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
	batchv1 "k8s.io/api/batch/v1"

	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/runs"
)

const backupsSpecURI = "https://vistaplatform.local/maintenance-service.openapi.yaml"

func backupsSpecCompiler(t *testing.T) *jsonschema.Compiler {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	specPath := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..", "api", "openapi", "maintenance-service.openapi.yaml")
	raw, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatal(err)
	}
	var asAny any
	if err := yaml.Unmarshal(raw, &asAny); err != nil {
		t.Fatal(err)
	}
	js, _ := json.Marshal(asAny)
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(js))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(backupsSpecURI, doc); err != nil {
		t.Fatal(err)
	}
	return c
}

func backupsConforms(t *testing.T, c *jsonschema.Compiler, schema string, body []byte) {
	t.Helper()
	sch, err := c.Compile(backupsSpecURI + "#/components/schemas/" + schema)
	if err != nil {
		t.Fatalf("compile %s: %v", schema, err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("body: %v\n%s", err, body)
	}
	if err := sch.Validate(inst); err != nil {
		t.Fatalf("response violates %s:\n%v\n--- body ---\n%s", schema, err, body)
	}
}

func TestContract_BackupsAndRuns(t *testing.T) {
	c := backupsSpecCompiler(t)
	bh := newBackupsHarness(t, 5)
	r := backupsEngine(bh.h)
	r.GET("/runs", runs.ListHandler(bh.runs))
	r.GET("/runs/:id", runs.GetHandler(bh.runs))

	// Empty list.
	w := backupsDo(r, http.MethodGet, "/backups", "")
	backupsConforms(t, c, "BackupList", w.Body.Bytes())

	// 400 / 202 / 409.
	backupsConforms(t, c, "Error", backupsDo(r, http.MethodPost, "/backups", `{"include_secrets":true}`).Body.Bytes())
	w = backupsDo(r, http.MethodPost, "/backups", `{}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("create %d", w.Code)
	}
	backupsConforms(t, c, "CreateBackupResponse", w.Body.Bytes())
	var created CreateResponse
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	conflict := backupsDo(r, http.MethodPost, "/backups", `{}`)
	if conflict.Code != http.StatusConflict {
		t.Fatalf("conflict %d", conflict.Code)
	}
	backupsConforms(t, c, "Error", conflict.Body.Bytes())

	// A running backup in the list (manifest null), then a ready one.
	backupsConforms(t, c, "BackupList", backupsDo(r, http.MethodGet, "/backups", "").Body.Bytes())
	bh.completeJob(created.Backup, dumpBytes(t, 500))
	bh.waitRun(created.Run.ID)
	w = backupsDo(r, http.MethodGet, "/backups", "")
	backupsConforms(t, c, "BackupList", w.Body.Bytes())
	if !bytes.Contains(w.Body.Bytes(), []byte(`"pg_dump_version"`)) {
		t.Fatalf("ready backup carries no manifest: %s", w.Body.Bytes())
	}

	// A failed run with steps and an error.
	b2, run2, err := bh.svc.Create(context.Background(), nil, CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_ = b2
	bh.setJob(JobName(b2.ID), batchv1.JobFailed)
	bh.waitRun(run2.ID)

	w = backupsDo(r, http.MethodGet, "/runs", "")
	backupsConforms(t, c, "MaintenanceRunList", w.Body.Bytes())
	w = backupsDo(r, http.MethodGet, "/runs/"+run2.ID.String(), "")
	if w.Code != http.StatusOK {
		t.Fatalf("get run %d", w.Code)
	}
	backupsConforms(t, c, "MaintenanceRun", w.Body.Bytes())
	backupsConforms(t, c, "Error", backupsDo(r, http.MethodGet, "/runs/nope", "").Body.Bytes())
	backupsConforms(t, c, "Error", backupsDo(r, http.MethodGet, "/runs?limit=500", "").Body.Bytes())
	backupsConforms(t, c, "Error", backupsDo(r, http.MethodGet, "/backups/"+run2.ID.String()+"/download", "").Body.Bytes())

	unavailable := NewHandlers(NewService(Config{}, nil, nil, nil, nil), nil, nil)
	w = backupsDo(backupsEngine(unavailable), http.MethodPost, "/backups", `{}`)
	backupsConforms(t, c, "Error", w.Body.Bytes())
}
