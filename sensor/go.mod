module github.com/vistasecurity/vistaplatform/sensor

go 1.26.5

require (
	github.com/vistasecurity/vistaplatform/shared v0.0.0
	github.com/google/uuid v1.6.0
	github.com/gopacket/gopacket v1.2.0
	golang.org/x/crypto v0.53.0
	golang.org/x/term v0.44.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/kr/pretty v0.3.1 // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	golang.org/x/sys v0.46.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
)

replace github.com/vistasecurity/vistaplatform/shared => ../shared
