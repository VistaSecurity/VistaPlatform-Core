module github.com/vistasecurity/vistaplatform/shared/rbac

go 1.26.5

require (
	github.com/vistasecurity/vistaplatform/shared v0.0.0
	github.com/google/uuid v1.6.0
	github.com/lib/pq v1.10.9
)

require github.com/golang-jwt/jwt/v5 v5.3.1 // indirect

replace github.com/vistasecurity/vistaplatform/shared => ../
