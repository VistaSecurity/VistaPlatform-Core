module github.com/vistasecurity/vistaplatform/scripts/database

go 1.26.5

require (
	github.com/vistasecurity/vistaplatform/shared v0.0.0
	github.com/google/uuid v1.6.0
	github.com/lib/pq v1.10.9
)

replace github.com/vistasecurity/vistaplatform/shared => ../../shared
