package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-agent/internal/config"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/hostinventory"
)

// A report the platform refuses on SIZE is a different kind of failure from
// every other submission error, and the client has to say which it was.
//
// Every other failure is worth trying again — the platform was restarting, the
// network blipped. This one is not: the same host produces the same size on the
// next run. A caller that cannot tell them apart is a caller that retries an
// over-cap report forever while the host never appears in the inventory, with
// the reason visible only in a log line nobody is reading.
//
// The measured length lives here because the agent is the only side that knows
// it: the platform stops reading at its cap, so the number in its 413 is what
// the request DECLARED.

func hostInventoryFixture() (*hostinventory.Report, *di.InterrogateResult) {
	return &hostinventory.Report{
			Collected: time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC),
			Mode:      hostinventory.ModeLocal,
			Platform:  hostinventory.PlatformLinux,
			Sections:  map[string]string{"host": hostinventory.SectionOK},
		}, &di.InterrogateResult{
			Assets:     []di.CryptoAsset{},
			DeviceInfo: map[string]interface{}{},
		}
}

func TestSubmitHostInventory_413IsATypedErrorCarryingTheMeasuredSize(t *testing.T) {
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		_, _ = w.Write([]byte(`{"error":"too big","max_bytes":33554432,"detail":"not a transient failure"}`))
	}))
	defer srv.Close()

	c := NewOutboundClient(&config.Config{PlatformURL: srv.URL, AgentID: uuid.New().String()})
	report, observations := hostInventoryFixture()

	err := c.SubmitHostInventory(report, observations)
	if err == nil {
		t.Fatal("a 413 was reported as success; the report was never stored")
	}

	// The category, for a caller that only needs to know it is not transient.
	if !errors.Is(err, ErrReportTooLarge) {
		t.Errorf("errors.Is(err, ErrReportTooLarge) = false for a 413: %v", err)
	}
	// The detail, for a caller that wants to say how far over the cap it was.
	var tooLarge *ReportTooLargeError
	if !errors.As(err, &tooLarge) {
		t.Fatalf("errors.As did not yield *ReportTooLargeError: %v", err)
	}
	if tooLarge.Bytes <= 0 {
		t.Errorf("the error carries no measured size (%d); an operator cannot see the gap", tooLarge.Bytes)
	}
	if tooLarge.Detail == "" {
		t.Error("the platform's explanation was dropped")
	}

	// One request. The client must not retry internally — that is what turns a
	// permanent condition into a loop.
	if requests != 1 {
		t.Errorf("the client made %d requests for one over-cap submission; it must not retry", requests)
	}
}

// The other polarity: an ordinary failure must NOT be classified as over-cap,
// or a transient blip would be reported as a permanent condition and stop
// anyone looking again.
func TestSubmitHostInventory_OtherFailuresAreNotReportTooLarge(t *testing.T) {
	for _, status := range []int{http.StatusInternalServerError, http.StatusBadRequest, http.StatusUnauthorized} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":"nope"}`))
		}))

		c := NewOutboundClient(&config.Config{PlatformURL: srv.URL, AgentID: uuid.New().String()})
		report, observations := hostInventoryFixture()
		err := c.SubmitHostInventory(report, observations)
		srv.Close()

		if err == nil {
			t.Errorf("status %d was reported as success", status)
			continue
		}
		if errors.Is(err, ErrReportTooLarge) {
			t.Errorf("status %d was misclassified as an over-cap report; a transient failure would "+
				"then be reported as permanent", status)
		}
	}
}

func TestSubmitHostInventory_AcceptedIsNotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"materialised"}`))
	}))
	defer srv.Close()

	c := NewOutboundClient(&config.Config{PlatformURL: srv.URL, AgentID: uuid.New().String()})
	report, observations := hostInventoryFixture()
	if err := c.SubmitHostInventory(report, observations); err != nil {
		t.Fatalf("202 Accepted was reported as a failure: %v", err)
	}
}

// The package list travels ONCE (asset-inventory 2.11b, BUILD_PLAN item 9).
//
// It used to ride the wire twice — once in `report.packages` and once in
// `observations.device_info.packages` — and the two were identical in size,
// because the projection enumerates every field a Package has. Measured on a
// real Ubuntu 24.04 collection that was 443 bytes per package across the whole
// submission, exactly half of it duplicate.
//
// The copy that survives is the OBSERVATIONS' one, and which one survives is
// not arbitrary: only that half has been through di.Sanitize, and it is the
// half the platform materialises into software_installs.
//
// To mutation-test: pass `report` instead of `withoutPackageList(report)` in
// SubmitHostInventory and the first assertion fails.
func TestSubmitHostInventory_ShipsThePackageListOnce(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	report, observations := hostInventoryFixture()
	report.Packages = []hostinventory.Package{{Name: "openssl", Version: "3.0.13", Manager: "dpkg"}}
	report.Sections[hostinventory.SectionPackages] = hostinventory.SectionOK
	observations.DeviceInfo["packages"] = []map[string]any{
		{"name": "openssl", "version": "3.0.13", "manager": "dpkg"},
	}

	c := NewOutboundClient(&config.Config{PlatformURL: srv.URL, AgentID: uuid.New().String()})
	if err := c.SubmitHostInventory(report, observations); err != nil {
		t.Fatalf("SubmitHostInventory: %v", err)
	}

	var sent struct {
		Report struct {
			Packages        []map[string]any  `json:"packages"`
			PackagesOmitted bool              `json:"packages_omitted"`
			Sections        map[string]string `json:"sections"`
		} `json:"report"`
		Observations struct {
			DeviceInfo map[string]any `json:"device_info"`
		} `json:"observations"`
	}
	if err := json.Unmarshal(body, &sent); err != nil {
		t.Fatalf("decode submission: %v", err)
	}

	if len(sent.Report.Packages) != 0 {
		t.Errorf("the report still carries %d package(s) on the wire; the list is duplicated",
			len(sent.Report.Packages))
	}
	if sent.Observations.DeviceInfo["packages"] == nil {
		t.Fatal("the surviving copy was dropped too; there is now no package list at all")
	}
	// Without the marker, an empty list under `sections.packages == "ok"` reads
	// as "we enumerated and found none" — the three-valued collapse the whole
	// Sections map exists to prevent.
	if !sent.Report.PackagesOmitted {
		t.Error("the elision is not marked; an empty list under a successful section reads as a host with no packages")
	}
	// The section outcome still travels, because it is the thing the marker
	// makes readable.
	if sent.Report.Sections[hostinventory.SectionPackages] != hostinventory.SectionOK {
		t.Errorf("the package section outcome was lost: %v", sent.Report.Sections)
	}

	// And the CALLER's report is untouched: --host-inventory-once prints it,
	// and the local record is the collector's own.
	if len(report.Packages) != 1 || report.PackagesOmitted {
		t.Errorf("the caller's own report was mutated: %d package(s), omitted=%t",
			len(report.Packages), report.PackagesOmitted)
	}
}

func TestWithoutPackageList_HandlesANilReport(t *testing.T) {
	if got := withoutPackageList(nil); got != nil {
		t.Fatalf("withoutPackageList(nil) = %+v, want nil", got)
	}
}

// The marker says a list was ELIDED, not that this function ran.
//
// It has to mean that, because the platform's intake reads it as a POSITIVE
// assertion and refuses a marked submission carrying no observations copy. Set
// unconditionally it would land on every report whose package step FAILED —
// which has no list to elide and no observations copy either — and turn every
// such host into a 400. That is the over-strict half of the same bug, and it is
// the half that breaks working deployments rather than letting a bad one
// through.
//
// Mutation check: set PackagesOmitted unconditionally and the second and third
// cases fail; drop it entirely and
// TestSubmitHostInventory_ShipsThePackageListOnce fails.
func TestWithoutPackageList_MarksOnlyWhenSomethingWasElided(t *testing.T) {
	sections := func(outcome string) map[string]string {
		return map[string]string{hostinventory.SectionPackages: outcome}
	}

	t.Run("a real list is dropped and marked", func(t *testing.T) {
		rep := &hostinventory.Report{
			Sections: sections(hostinventory.SectionOK),
			Packages: []hostinventory.Package{{Name: "openssl", Version: "3.0.13"}},
		}
		got := withoutPackageList(rep)
		if len(got.Packages) != 0 || !got.PackagesOmitted {
			t.Fatalf("packages = %d, omitted = %t", len(got.Packages), got.PackagesOmitted)
		}
	})

	t.Run("a FAILED package step is not marked", func(t *testing.T) {
		rep := &hostinventory.Report{Sections: sections(hostinventory.SectionFailed)}
		if got := withoutPackageList(rep); got.PackagesOmitted {
			t.Error("a report with no list to elide claims one was elided; the intake would 400 it")
		}
	})

	t.Run("a host with genuinely no packages is not marked", func(t *testing.T) {
		rep := &hostinventory.Report{Sections: sections(hostinventory.SectionOK)}
		if got := withoutPackageList(rep); got.PackagesOmitted {
			t.Error("an empty-but-successful enumeration claims a list was elided")
		}
	})
}
