package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// Integration test setup
func setupIntegrationTest(t *testing.T) *gin.Engine {
	gin.SetMode(gin.TestMode)

	handler := &Handler{}
	// Use a no-op logger so handlers don't panic on h.log (nil pointer); discard output.
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	handler.SetLogger(logger)
	router := gin.New()

	// Set up routes
	sensorManager := router.Group("/api/v1/sensor-manager")
	{
		sensorManager.POST("/sensors/pending", func(c *gin.Context) {
			c.Set("tenantID", uuid.New())
			handler.CreatePendingSensor(c)
		})
		sensorManager.POST("/sensors/register", handler.RegisterSensor)
		sensorManager.GET("/sensors/pending", func(c *gin.Context) {
			c.Set("tenantID", uuid.New())
			handler.GetPendingSensors(c)
		})
		sensorManager.DELETE("/sensors/pending/:key", handler.DeletePendingSensor)
		sensorManager.GET("/admin/settings", handler.GetAdminSettings)
		sensorManager.PUT("/admin/settings", handler.UpdateAdminSettings)
	}

	return router
}

func TestSensorRegistrationWorkflow_Validation(t *testing.T) {
	router := setupIntegrationTest(t)

	t.Run("CreatePendingSensor_Validation", func(t *testing.T) {
		payload := map[string]interface{}{
			"name":               "test-sensor",
			"ip_address":         "192.168.1.100",
			"profile":            "datacenter_host",
			"network_interfaces": []string{"eth0"},
			"tags":               []string{"test"},
			"description":        "Integration test sensor",
		}

		jsonBody, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/api/v1/sensor-manager/sensors/pending", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		// Should fail due to nil sensor service, but validation should pass
		assert.Equal(t, 500, w.Code)
	})

	t.Run("RegisterSensor_Validation", func(t *testing.T) {
		payload := map[string]interface{}{
			"registration_key":   "REG-test-123",
			"name":               "test-sensor",
			"platform":           "linux",
			"version":            "1.0.0",
			"profile":            "datacenter_host",
			"network_interfaces": []string{"eth0"},
			"ip_address":         "192.168.1.100",
			"tags":               []string{"test"},
			"description":        "Integration test sensor",
		}

		jsonBody, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/api/v1/sensor-manager/sensors/register", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		// Should fail due to nil sensor service, but validation should pass
		assert.Equal(t, 500, w.Code, "expected 500 when sensor service is nil")

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.NotNil(t, response["error"], "expected error in response body")
		assert.Contains(t, fmt.Sprint(response["error"]), "Sensor service not initialized")
	})

	t.Run("GetPendingSensors_Validation", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/sensor-manager/sensors/pending", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		// Should fail due to nil sensor service, but validation should pass
		assert.Equal(t, 500, w.Code)
	})

	t.Run("DeletePendingSensor_Validation", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/api/v1/sensor-manager/sensors/pending/test-key", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		// Should fail with 400 Bad Request (validation error) or 404 Not Found
		assert.Contains(t, []int{400, 404}, w.Code)
	})
}

func TestSensorRegistrationWorkflow_ErrorCases(t *testing.T) {
	router := setupIntegrationTest(t)

	t.Run("RegisterSensor_InvalidIP", func(t *testing.T) {
		payload := map[string]interface{}{
			"registration_key":   "REG-test-123",
			"name":               "test-sensor",
			"platform":           "linux",
			"version":            "1.0.0",
			"profile":            "datacenter_host",
			"network_interfaces": []string{"eth0"},
			"ip_address":         "invalid-ip",
		}

		jsonBody, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/api/v1/sensor-manager/sensors/register", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, 400, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "Invalid IP address format")
	})

	t.Run("RegisterSensor_MissingRequiredFields", func(t *testing.T) {
		payload := map[string]interface{}{
			"registration_key": "REG-test-123",
			"name":             "test-sensor",
			// Missing required fields
		}

		jsonBody, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/api/v1/sensor-manager/sensors/register", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, 400, w.Code)
	})

	t.Run("CreatePendingSensor_InvalidIP", func(t *testing.T) {
		payload := map[string]interface{}{
			"name":       "test-sensor",
			"ip_address": "invalid-ip",
			"profile":    "datacenter_host",
		}

		jsonBody, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/api/v1/sensor-manager/sensors/pending", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, 400, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "Invalid IP address format")
	})
}

func TestAdminSettings_Integration(t *testing.T) {
	router := setupIntegrationTest(t)

	t.Run("GetAdminSettings", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/sensor-manager/admin/settings", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)

		assert.Contains(t, response, "key_expiration_minutes")
		assert.Contains(t, response, "max_pending_sensors")
		assert.Contains(t, response, "require_ip_validation")
	})

	t.Run("UpdateAdminSettings_Valid", func(t *testing.T) {
		payload := map[string]interface{}{
			"key_expiration_minutes": 120,
			"max_pending_sensors":    100,
			"require_ip_validation":  true,
		}

		jsonBody, _ := json.Marshal(payload)
		req := httptest.NewRequest("PUT", "/api/v1/sensor-manager/admin/settings", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "Admin settings updated successfully", response["message"])
	})

	t.Run("UpdateAdminSettings_Invalid", func(t *testing.T) {
		payload := map[string]interface{}{
			"key_expiration_minutes": 2, // Too short
			"max_pending_sensors":    100,
			"require_ip_validation":  true,
		}

		jsonBody, _ := json.Marshal(payload)
		req := httptest.NewRequest("PUT", "/api/v1/sensor-manager/admin/settings", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, 400, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "Key expiration must be between 5 and 1440 minutes")
	})
}
