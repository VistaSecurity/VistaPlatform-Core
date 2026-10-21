module github.com/vistasecurity/vistaplatform/device-agent

go 1.26.10

require (
	github.com/google/uuid v1.6.0
	github.com/vistasecurity/vistaplatform/shared v0.0.0
	golang.org/x/term v0.47.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/go-sql-driver/mysql v1.10.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/lib/pq v1.12.3 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/net v0.61.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
)

replace github.com/vistasecurity/vistaplatform/shared => ../shared
