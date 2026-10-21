module github.com/vistasecurity/vistaplatform/sensor

go 1.26.10

require (
	github.com/google/uuid v1.6.0
	github.com/gopacket/gopacket v1.7.4
	github.com/vistasecurity/vistaplatform/shared v0.0.0
	golang.org/x/crypto v0.58.0
	golang.org/x/net v0.61.0
	golang.org/x/sys v0.49.0
	golang.org/x/term v0.47.0
	gopkg.in/yaml.v3 v3.0.1
)

require github.com/kr/text v0.2.0 // indirect

replace github.com/vistasecurity/vistaplatform/shared => ../shared
