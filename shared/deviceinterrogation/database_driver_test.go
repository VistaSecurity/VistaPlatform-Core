package deviceinterrogation

import (
	"context"
	"database/sql"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

// MySQL interrogation must reach the network.
//
// `mysql` has been a registered device type since the collector was written,
// but nothing registered a `database/sql` driver under that name, so every
// MySQL interrogation — in-cluster and on the standalone agent alike — failed
// inside sql.Open with `sql: unknown driver "mysql"` before a packet was sent
// (M-08). A test that stubs dbInterrogateMy cannot see that; these drive the
// real function.

func TestMySQLDriver_IsRegistered(t *testing.T) {
	if !slices.Contains(sql.Drivers(), "mysql") {
		t.Fatalf("no database/sql driver is registered as %q (registered: %v); every mysql interrogation fails before dialling", "mysql", sql.Drivers())
	}
}

// The DSN dbBuildConnStr produces must be one the registered driver accepts —
// a driver that parses a different DSN grammar fails exactly like no driver.
func TestMySQLDriver_AcceptsTheBuiltDSN(t *testing.T) {
	for _, tc := range []struct {
		name   string
		device DeviceInfo
		creds  Credentials
	}{
		{"hostname", DeviceInfo{DeviceType: "mysql", Hostname: "db.example.test"}, Credentials{Username: "audit", Password: "s3cret"}},
		{"ipv4", DeviceInfo{DeviceType: "mysql", IPAddress: "192.0.2.41"}, Credentials{Username: "audit", Password: "s3cret"}},
		{"password with DSN metacharacters", DeviceInfo{DeviceType: "mysql", IPAddress: "192.0.2.41"}, Credentials{Username: "audit", Password: "p@ss:w/rd(1)?x=y"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dsn, port, err := dbBuildConnStr(tc.device, tc.creds)
			if err != nil {
				t.Fatalf("dbBuildConnStr: %v", err)
			}
			if port != 3306 {
				t.Errorf("port = %d, want 3306", port)
			}
			cfg, err := mysqlConfig(dsn)
			if err != nil {
				t.Fatalf("the driver rejects the DSN dbBuildConnStr built: %v", err)
			}
			if cfg.User != tc.creds.Username || cfg.Passwd != tc.creds.Password {
				t.Errorf("credentials did not round-trip: user=%q", cfg.User)
			}
			// The driver's default is no TLS; "preferred" is the
			// sslmode=prefer the PostgreSQL DSN asks for.
			if cfg.TLSConfig != "preferred" {
				t.Errorf("tls = %q, want %q", cfg.TLSConfig, "preferred")
			}
			// The driver's default logger writes to stderr.
			if _, ok := cfg.Logger.(*mysql.NopLogger); !ok {
				t.Errorf("logger = %T, want *mysql.NopLogger", cfg.Logger)
			}
			host, _ := deviceHost(tc.device)
			if want := net.JoinHostPort(host, "3306"); cfg.Addr != want {
				t.Errorf("addr = %q, want %q", cfg.Addr, want)
			}
		})
	}
}

// The wiring: the real dbInterrogateMySQL, pointed at a port nothing listens
// on, must fail DIALLING — not before it.
func TestMySQLInterrogation_ReachesTheNetwork(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close() // now refused

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = InterrogateMySQLConn(ctx, "audit:s3cret@tcp("+addr+")/")
	if err == nil {
		t.Fatal("interrogating a closed port succeeded")
	}
	if strings.Contains(err.Error(), "unknown driver") {
		t.Fatalf("MySQL interrogation fails before dialling: %v", err)
	}
	if !strings.Contains(err.Error(), "ping MySQL") {
		t.Errorf("want the failure to come from the connection attempt, got: %v", err)
	}
}
