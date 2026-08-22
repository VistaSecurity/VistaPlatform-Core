package handlers

import (
	"database/sql"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

// AdminSensor is one row of the platform-admin, cross-tenant Fleet view.
//
// It mirrors the tenant-scoped sensor list (services.SensorServiceV2.ListSensors)
// but (1) is NOT filtered by tenant and (2) carries tenant identity on every row
// so the VISTA Operations Fleet view can attribute each sensor to its owner.
//
// Field semantics match the canonical Sensor model (internal/models/sensor.go):
// every column here is a real `sensors`/`tenants` column — no invented fields.
type AdminSensor struct {
	ID         uuid.UUID `json:"id"`
	TenantID   uuid.UUID `json:"tenant_id"`
	TenantName string    `json:"tenant_name"`
	TenantSlug string    `json:"tenant_slug"`

	Name        string  `json:"name"`
	Description *string `json:"description"`
	SensorType  string  `json:"sensor_type"` // 'network', 'endpoint', 'cloud', 'api'
	Platform    string  `json:"platform"`    // "platform" for the in-cluster Platform Sensor
	Version     string  `json:"version"`     // "system" for the Platform Sensor
	Profile     string  `json:"profile"`     // "discovery" for the Platform Sensor
	Status      string  `json:"status"`      // 'pending','active','inactive','error','offline'
	AirGapped   bool    `json:"air_gapped"`

	NetworkInterfaces   []string `json:"network_interfaces"`
	AvailableInterfaces []string `json:"available_interfaces"`
	Tags                []string `json:"tags"`
	IPAddress           *string  `json:"ip_address"`

	// IsPlatformSensor flags the in-cluster Platform Sensor registered by
	// cluster-sensor-service for every tenant. There is no dedicated column for
	// this; it is derived from the registration signature (platform='platform').
	IsPlatformSensor bool `json:"is_platform_sensor"`

	LastHeartbeat *time.Time `json:"last_heartbeat"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// GetAdminSensors lists sensors across ALL tenants for the VISTA Operations
// Fleet view. Platform-admin gated (see router) and strictly READ-ONLY.
//
// Cross-tenant by design: unlike the tenant-scoped list, the query deliberately
// omits the `WHERE tenant_id = ...` filter. RLS is inert in this codebase, so
// the tenant filter is the only isolation on the tenant-facing endpoint; this
// admin variant intentionally drops it and is fenced off by RequirePlatformAdmin.
func (h *Handler) GetAdminSensors(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusOK, gin.H{"sensors": []interface{}{}})
		return
	}

	// Optional operator-scope narrowing: filter the cross-tenant roll-up to one
	// tenant server-side, so other tenants' rows are never shipped to the client.
	// Validate as a UUID (reject a malformed value with 400 rather than letting it
	// surface as a 500 from the typed tenant_id column).
	tenantFilter := c.Query("tenant_id")
	if tenantFilter != "" {
		if _, err := uuid.Parse(tenantFilter); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant_id"})
			return
		}
	}

	// Reuses the column set of ListSensorsByTenant, minus the tenant filter,
	// plus a cheap join to tenants for identity and the sensor_type column.
	query := `
		SELECT s.id, s.tenant_id, t.name, t.slug,
		       s.name, s.description, s.sensor_type, s.platform, s.version, s.profile, s.status,
		       s.air_gapped, s.network_interfaces, s.available_interfaces, s.tags, s.ip_address,
		       s.last_heartbeat, s.created_at, s.updated_at
		FROM sensors s
		LEFT JOIN tenants t ON t.id = s.tenant_id
		WHERE s.deleted_at IS NULL`

	var args []interface{}
	if tenantFilter != "" {
		query += " AND s.tenant_id = $1"
		args = append(args, tenantFilter)
	}
	query += " ORDER BY t.name NULLS LAST, s.created_at DESC"

	// RLS: cross-tenant — runs on the bypass role. This is the platform-admin
	// roll-up across every tenant (the optional tenant_id filter narrows it
	// server-side but is not a tenant *context*), so app.tenant_id cannot be set.
	// On the RLS-scoped handle it returns an empty list and a 200.
	if h.bypassDB == nil {
		c.JSON(http.StatusOK, gin.H{"sensors": []interface{}{}})
		return
	}
	rows, err := h.bypassDB.QueryContext(c.Request.Context(), query, args...)
	if err != nil {
		log.Printf("⚠️  Error listing admin (cross-tenant) sensors: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list sensors"})
		return
	}
	defer func() { _ = rows.Close() }()

	sensors := make([]AdminSensor, 0)
	for rows.Next() {
		var s AdminSensor
		var description, platform, version, profile, ipAddress sql.NullString
		var tenantName, tenantSlug, sensorType sql.NullString

		if err := rows.Scan(
			&s.ID, &s.TenantID, &tenantName, &tenantSlug,
			&s.Name, &description, &sensorType, &platform, &version, &profile, &s.Status,
			&s.AirGapped, pq.Array(&s.NetworkInterfaces), pq.Array(&s.AvailableInterfaces), pq.Array(&s.Tags), &ipAddress,
			&s.LastHeartbeat, &s.CreatedAt, &s.UpdatedAt,
		); err != nil {
			log.Printf("⚠️  Error scanning admin sensor row: %v", err)
			continue
		}

		s.TenantName = tenantName.String
		s.TenantSlug = tenantSlug.String
		if description.Valid {
			s.Description = &description.String
		}
		s.SensorType = orUnknown(sensorType)
		s.Platform = orUnknown(platform)
		s.Version = orUnknown(version)
		s.Profile = orUnknown(profile)
		if ipAddress.Valid && ipAddress.String != "" {
			s.IPAddress = &ipAddress.String
		}
		// The in-cluster Platform Sensor is registered by cluster-sensor-service
		// with platform="platform" (see cluster-sensor-service auto_register.go).
		s.IsPlatformSensor = platform.Valid && platform.String == "platform"

		sensors = append(sensors, s)
	}

	c.JSON(http.StatusOK, gin.H{"sensors": sensors, "count": len(sensors)})
}

func orUnknown(s sql.NullString) string {
	if s.Valid && s.String != "" {
		return s.String
	}
	return "unknown"
}
