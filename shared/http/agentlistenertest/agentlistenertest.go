// Package agentlistenertest drives a service's agent/sensor mTLS passthrough
// listener in tests the way production does, and checks that listener's route
// surface against the HTTP calls the sensor and device-agent binaries
// actually make.
//
// It exists for one class of bug: the passthrough listener skips every edge
// deny, so it must serve only the agent routes (shared/http AgentRoutes), and
// a new agent call that is not on that list would silently 404 in the field.
package agentlistenertest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"go/ast"
	"go/parser"
	"go/token"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Listener is a running agent listener and a client that presents a
// self-signed client certificate to it: exactly what an attacker who can
// reach the passthrough port can present (the handshake requires a client
// certificate but cannot verify it; the agent auth middleware does).
type Listener struct {
	URL    string
	Client *http.Client
}

// WriteServerCert writes a throwaway server certificate and key into a test
// temp dir and returns their paths, for building the listener with the same
// constructor main uses.
func WriteServerCert(t testing.TB) (certPath, keyPath string) {
	t.Helper()
	certPEM, keyPEM := selfSigned(t, "agent-listener-test-server", []string{"127.0.0.1"})
	dir := t.TempDir()
	certPath = filepath.Join(dir, "tls.crt")
	keyPath = filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("writing server cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("writing server key: %v", err)
	}
	return certPath, keyPath
}

// Serve starts srv (as built by the service's own constructor) on a loopback
// port over TLS and returns a client presenting a self-signed client
// certificate whose CN is clientCN. The server is closed when the test ends.
func Serve(t testing.TB, srv *http.Server, clientCN string) *Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })

	certPEM, keyPEM := selfSigned(t, clientCN, nil)
	clientCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("client key pair: %v", err)
	}
	return &Listener{
		URL: "https://" + ln.Addr().String(),
		Client: &http.Client{
			Timeout: 10 * time.Second,
			// Never follow a redirect: a trailing-slash redirect must be seen
			// as what it is, not as the answer of wherever it points.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport: &http.Transport{TLSClientConfig: &tls.Config{
				Certificates:       []tls.Certificate{clientCert},
				InsecureSkipVerify: true, //nolint:gosec // test server's throwaway cert; the listener under test is the server
				MinVersion:         tls.VersionTLS12,
			}},
		},
	}
}

func selfSigned(t testing.TB, cn string, ips []string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	for _, ip := range ips {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP(ip))
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshalling key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// ClientCall is one HTTP call a sensor or device-agent binary makes to a
// platform service: the method and the path's fmt format ("%s" for each value
// filled in at run time), and where it is made.
type ClientCall struct {
	Method string
	Format string
	Func   string
	Pos    string
}

// ScanClientCalls finds every call the Go sources under roots make to a path
// beginning with servicePrefix (e.g. "/api/v1/sensor-manager/"). It recognises
// the clients' one construction:
//
//	url := fmt.Sprintf("%s/api/v1/<service>/...", c.baseURL, ...)
//	req, err := http.NewRequest("POST", url, ...)
//
// and FAILS on any string mentioning servicePrefix that it cannot pair with a
// request, so a call written another way is reported rather than skipped.
// Test files are ignored.
func ScanClientCalls(t testing.TB, servicePrefix string, roots ...string) []ClientCall {
	t.Helper()
	var calls []ClientCall
	for _, root := range roots {
		err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			calls = append(calls, scanFile(t, p, servicePrefix)...)
			return nil
		})
		if err != nil {
			t.Fatalf("scanning %s: %v", root, err)
		}
	}
	return calls
}

func scanFile(t testing.TB, file, servicePrefix string) []ClientCall {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", file, err)
	}

	// Every literal naming the service must be accounted for by a call.
	mentions := map[token.Pos]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING && strings.Contains(lit.Value, servicePrefix) {
			mentions[lit.Pos()] = false
		}
		return true
	})
	if len(mentions) == 0 {
		return nil
	}

	var calls []ClientCall
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		formats := map[string]*ast.BasicLit{} // variable -> its fmt.Sprintf format
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.AssignStmt:
				if len(n.Lhs) != 1 || len(n.Rhs) != 1 {
					return true
				}
				id, ok := n.Lhs[0].(*ast.Ident)
				if !ok {
					return true
				}
				if lit := sprintfFormat(n.Rhs[0]); lit != nil && strings.Contains(lit.Value, servicePrefix) {
					formats[id.Name] = lit
				}
			case *ast.CallExpr:
				method, urlArg, ok := newRequestArgs(n)
				if !ok {
					return true
				}
				id, ok := urlArg.(*ast.Ident)
				if !ok {
					return true
				}
				lit, ok := formats[id.Name]
				if !ok {
					return true
				}
				format, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatalf("%s: unquoting %s: %v", fset.Position(lit.Pos()), lit.Value, err)
				}
				// The format starts with the base URL ("%s/api/...").
				format = strings.TrimPrefix(format, "%s")
				if i := strings.IndexByte(format, '?'); i >= 0 {
					format = format[:i]
				}
				calls = append(calls, ClientCall{
					Method: method,
					Format: format,
					Func:   fn.Name.Name,
					Pos:    fset.Position(n.Pos()).String(),
				})
				mentions[lit.Pos()] = true
			}
			return true
		})
	}
	for pos, used := range mentions {
		if !used {
			t.Errorf("%s: a string names %s but is not a recognised `url := fmt.Sprintf(...)` + `http.NewRequest(method, url, ...)` call; teach agentlistenertest.ScanClientCalls this construction so the agent listener's route list can be checked against it",
				fset.Position(pos), servicePrefix)
		}
	}
	return calls
}

func sprintfFormat(e ast.Expr) *ast.BasicLit {
	call, ok := e.(*ast.CallExpr)
	if !ok || len(call.Args) == 0 || !isSelector(call.Fun, "fmt", "Sprintf") {
		return nil
	}
	lit, ok := call.Args[0].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return nil
	}
	return lit
}

// newRequestArgs recognises http.NewRequest(method, url, body) and
// http.NewRequestWithContext(ctx, method, url, body).
func newRequestArgs(call *ast.CallExpr) (method string, url ast.Expr, ok bool) {
	var mArg, uArg ast.Expr
	switch {
	case isSelector(call.Fun, "http", "NewRequest") && len(call.Args) == 3:
		mArg, uArg = call.Args[0], call.Args[1]
	case isSelector(call.Fun, "http", "NewRequestWithContext") && len(call.Args) == 4:
		mArg, uArg = call.Args[1], call.Args[2]
	default:
		return "", nil, false
	}
	switch m := mArg.(type) {
	case *ast.BasicLit:
		s, err := strconv.Unquote(m.Value)
		if err != nil {
			return "", nil, false
		}
		return strings.ToUpper(s), uArg, true
	case *ast.SelectorExpr:
		if x, ok := m.X.(*ast.Ident); ok && x.Name == "http" && strings.HasPrefix(m.Sel.Name, "Method") {
			return strings.ToUpper(strings.TrimPrefix(m.Sel.Name, "Method")), uArg, true
		}
	}
	return "", nil, false
}

func isSelector(e ast.Expr, pkg, name string) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	x, ok := sel.X.(*ast.Ident)
	return ok && x.Name == pkg
}

// FormatMatchesRoute reports whether a client path format ("%s" for a value
// filled in at run time) is served by the gin route pattern (":param" for a
// path parameter, "*rest" for a catch-all).
func FormatMatchesRoute(format, route string) bool {
	fs := strings.Split(strings.Trim(format, "/"), "/")
	rs := strings.Split(strings.Trim(route, "/"), "/")
	for i, r := range rs {
		if strings.HasPrefix(r, "*") {
			return i < len(fs)
		}
		if i >= len(fs) {
			return false
		}
		switch {
		case strings.HasPrefix(r, ":"):
			// A parameter takes any one segment.
		case strings.Contains(fs[i], "%"):
			// A run-time value can only fill a parameter.
			return false
		case r != fs[i]:
			return false
		}
	}
	return len(fs) == len(rs)
}
