package deviceinterrogation

import (
	"context"
	"encoding/xml"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The classifier branches the vendor tests do not reach on their own.

type timeoutNetError struct{}

func (timeoutNetError) Error() string   { return "i/o timeout" }
func (timeoutNetError) Timeout() bool   { return true }
func (timeoutNetError) Temporary() bool { return true }

func TestClassifyWarningReason_RemainingBranches(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want WarningReason
	}{
		{"405", statusErrorf(http.StatusMethodNotAllowed, "x"), WarningNotSupported},
		{"401", statusErrorf(http.StatusUnauthorized, "x"), WarningPermissionDenied},
		{"408", statusErrorf(http.StatusRequestTimeout, "x"), WarningTimeout},
		{"os deadline", fmt.Errorf("read: %w", os.ErrDeadlineExceeded), WarningTimeout},
		{"net.Error timeout", fmt.Errorf("read: %w", timeoutNetError{}), WarningTimeout},
		{"context deadline", fmt.Errorf("get: %w", context.DeadlineExceeded), WarningTimeout},
		{"bare ECONNREFUSED", fmt.Errorf("connect: %w", syscall.ECONNREFUSED), WarningUnreachable},
		{"EHOSTUNREACH", fmt.Errorf("connect: %w", syscall.EHOSTUNREACH), WarningUnreachable},
		{"dial op", &net.OpError{Op: "dial", Net: "tcp", Err: fmt.Errorf("refused")}, WarningUnreachable},
		{"read op is not a dial", &net.OpError{Op: "read", Net: "tcp", Err: fmt.Errorf("reset")}, WarningError},
		{"xml syntax", fmt.Errorf("decode: %w", &xml.SyntaxError{Msg: "x", Line: 1}), WarningParseError},
		{"PAN-OS 16", panAPIError("16", "show arp all"), WarningPermissionDenied},
		{"PAN-OS 403", panAPIError("403", "show arp all"), WarningPermissionDenied},
		{"PAN-OS 1", panAPIError("1", "show arp all"), WarningNotSupported},
		{"PAN-OS 17", panAPIError("17", "show arp all"), WarningNotSupported},
		{"PAN-OS 7", panAPIError("7", "show arp all"), WarningError},
		{"UniFi NoPermission", unifiAPIError("api.err.NoPermission"), WarningPermissionDenied},
		{"UniFi LoginRequired", unifiAPIError("api.err.LoginRequired"), WarningPermissionDenied},
		{"UniFi other", unifiAPIError("api.err.Invalid"), WarningError},
		{"SNMP authorizationError (16)", snmpStatusError(16), WarningPermissionDenied},
		{"SNMP noAccess (6)", snmpStatusError(6), WarningPermissionDenied},
		{"SNMP genErr (5)", snmpStatusError(5), WarningError},
		{"SNMP no response before deadline", reasonErrorf(WarningTimeout, "no SNMP response"), WarningTimeout},
	}
	for _, c := range cases {
		if got := ClassifyWarningReason(c.err); got != c.want {
			t.Errorf("%s: ClassifyWarningReason(%v) = %q, want %q", c.name, c.err, got, c.want)
		}
	}
}

// A walk cut by the collection DEADLINE (not the row cap) is a timeout
// warning naming the column: the device was too slow to walk in the time one
// interrogation has. The rows that were read are kept.
func TestSNMPWalkColumn_DeadlineCutIsATimeoutWarning(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = conn.Close() }()
	go func() {
		buf := make([]byte, snmpMaxResponseBytes)
		next := 0
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			next++
			// Slow enough that the deadline, not the 500-row cap, ends the walk.
			time.Sleep(20 * time.Millisecond)
			reply, err := snmpTestAnswer(append([]byte(nil), buf[:n]...), []snmpTestValue{
				snmpTestOctet(snmpOIDIfDescr+"."+itoa(next), "Gi1/0/"+itoa(next)),
			})
			if err != nil {
				continue
			}
			_, _ = conn.WriteTo(reply, addr)
		}
	}()
	client, err := net.Dial("udp", conn.LocalAddr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	result := &InterrogateResult{collector: snmpCollector}
	rows, truncated := snmpWalkColumn(context.Background(), result, client, "public", snmpOIDIfDescr, time.Second, time.Now().Add(400*time.Millisecond))
	if !truncated || len(rows) == 0 || len(rows) >= snmpMaxWalkRows {
		t.Fatalf("fixture: want a deadline-cut walk with some rows, got %d rows truncated=%v", len(rows), truncated)
	}
	if len(result.Warnings) != 1 {
		t.Fatalf("want one warning, got %+v", result.Warnings)
	}
	w := result.Warnings[0]
	if w.Reason != WarningTimeout || !strings.Contains(w.Endpoint, "ifDescr") || !strings.Contains(w.Effect, strconv.Itoa(len(rows))) {
		t.Errorf("deadline-cut walk warning = %+v; want timeout, naming ifDescr and the %d rows read", w, len(rows))
	}

	// The live walk above usually ends inside an exchange (a read timeout,
	// the error branch). A walk whose budget is spent BEFORE an exchange takes
	// the other branch — cut, no error — deterministically, and must say the
	// same thing.
	spent := &InterrogateResult{collector: snmpCollector}
	if _, cut := snmpWalkColumn(context.Background(), spent, client, "public", snmpOIDIfName, time.Second, time.Now()); !cut {
		t.Fatal("fixture: a walk with no budget left did not report itself cut")
	}
	if len(spent.Warnings) != 1 || spent.Warnings[0].Reason != WarningTimeout || !strings.Contains(spent.Warnings[0].Endpoint, "ifName") {
		t.Errorf("a walk cut by a spent deadline raised %+v; want one timeout warning naming ifName", spent.Warnings)
	}
}

// FortiOS: a routing table past fortinetMaxRouteRows is counted from its first
// rows and says so, through the real interrogator.
func TestFortinetInterrogator_RouteTableCutIsATruncatedWarning(t *testing.T) {
	var routes strings.Builder
	routes.WriteString(`{"status":"success","results":[`)
	for i := 0; i <= fortinetMaxRouteRows; i++ {
		if i > 0 {
			routes.WriteByte(',')
		}
		routes.WriteString(`{"gateway":"192.0.2.1"}`)
	}
	routes.WriteString(`]}`)
	body := routes.String()

	fixture := newFortinetOpsTestServer(t)
	fixture.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/monitor/router/ipv4") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
			return
		}
		fixture.Config.Handler.ServeHTTP(w, r)
	}))
	defer srv.Close()

	result := interrogateVia(t, "fortigate", DeviceInfo{ManagementURL: srv.URL})
	w := findWarning(t, result, "/api/v2/monitor/router/ipv4")
	if w.Reason != WarningTruncated || !strings.Contains(w.Effect, strconv.Itoa(fortinetMaxRouteRows)) {
		t.Errorf("route-table warning = %+v; want truncated naming the %d-row bound", w, fortinetMaxRouteRows)
	}
	if !hasFact(result, factNetRouteNextHopCount) {
		t.Error("the next-hop count from the rows that were read was dropped")
	}
}

// Cisco: only the first lines are read for a refusal, each on its own, and
// the output never becomes the detail.
func TestCiscoRun_AuthorizationRefusal(t *testing.T) {
	run := func(out string) ciscoRunner {
		return func(context.Context, string) (string, bool, error) { return out, false, nil }
	}

	// A refusal: permission denied, fixed detail, no output parsed.
	refused := &InterrogateResult{collector: ciscoCollector}
	if _, ok := ciscoRun(context.Background(), refused, run("\n% Authorization failed.\nSECRETOUTPUT9\n"), "show ip arp", "ARP"); ok {
		t.Error("a refused command's output was handed to the parser")
	}
	if len(refused.Warnings) != 1 || refused.Warnings[0].Reason != WarningPermissionDenied ||
		strings.Contains(refused.Warnings[0].Detail, "SECRETOUTPUT9") || strings.Contains(refused.Warnings[0].Detail, "Authorization failed") {
		t.Errorf("refusal warning = %+v; want permission_denied with a fixed detail", refused.Warnings)
	}

	// The same words deep inside real output are data, not a refusal.
	var long strings.Builder
	for i := 0; i < 10; i++ {
		long.WriteString("Gi1/0/" + strconv.Itoa(i) + " up up\n")
	}
	// A line past the first few that is exactly what a refusal looks like —
	// in a banner, a description, a pasted log — is still data.
	long.WriteString("% Authorization failed.\n")
	ok := &InterrogateResult{collector: ciscoCollector}
	if out, parsed := ciscoRun(context.Background(), ok, run(long.String()), "show interfaces", "Interfaces"); !parsed || out == "" {
		t.Error("output mentioning an authorization failure past the first lines was thrown away")
	}
	if len(ok.Warnings) != 0 {
		t.Errorf("a warning was raised for output that was not a refusal: %+v", ok.Warnings)
	}
}
