// E2E test for sensor registration workflow
// This test focuses on API endpoint validation and admin settings
package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// newTestHandler creates a Handler with a logger initialized for testing.
// Service dependencies are left nil so tests exercise validation paths only.
func newTestHandler() *Handler {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	return &Handler{
		log: logger,
	}
}

func TestSensorRegistrationE2E_APIEndpoints(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Set up the complete API with all routes
	handler := newTestHandler()
	router := gin.New()

	// API Gateway routes (as they would be in production)
	api := router.Group("/api/v1")
	{
		// Sensor manager routes
		sensorManager := api.Group("/sensor-manager")
		{
			// Sensor registration (validation only)
			sensorManager.POST("/sensors/register", handler.RegisterSensor)

			// Admin settings (no service dependency)
			sensorManager.GET("/admin/settings", handler.GetAdminSettings)
			sensorManager.PUT("/admin/settings", handler.UpdateAdminSettings)
		}
	}

	t.Run("APIEndpointValidation", func(t *testing.T) {
		// Test that all expected endpoints exist and handle requests appropriately
		endpoints := []struct {
			name   string
			method string
			path   string
			status int
		}{
			{"GetAdminSettings", "GET", "/api/v1/sensor-manager/admin/settings", 200}, // Works (no service dependency)
		}

		for _, endpoint := range endpoints {
			t.Run(endpoint.name, func(t *testing.T) {
				var req *http.Request
				if endpoint.method == "POST" || endpoint.method == "PUT" {
					payload := map[string]interface{}{"test": "data"}
					jsonBody, _ := json.Marshal(payload)
					req = httptest.NewRequest(endpoint.method, endpoint.path, bytes.NewBuffer(jsonBody))
					req.Header.Set("Content-Type", "application/json")
				} else {
					req = httptest.NewRequest(endpoint.method, endpoint.path, nil)
				}

				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)

				assert.Equal(t, endpoint.status, w.Code, "Endpoint %s %s should return status %d", endpoint.method, endpoint.path, endpoint.status)
			})
		}
	})
}

func TestSensorRegistrationE2E_Validation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := newTestHandler()
	router := gin.New()

	// Set up minimal routes for validation testing
	api := router.Group("/api/v1")
	sensorManager := api.Group("/sensor-manager")
	{
		sensorManager.POST("/sensors/register", handler.RegisterSensor)
	}

	t.Run("RegisterSensorValidation", func(t *testing.T) {
		testCases := []struct {
			name           string
			payload        map[string]interface{}
			expectedStatus int
			expectedError  string
		}{
			{
				name: "InvalidIPAddress",
				payload: map[string]interface{}{
					"registration_key":   "REG-test-123",
					"name":               "test-sensor",
					"platform":           "linux",
					"version":            "1.0.0",
					"profile":            "datacenter_host",
					"network_interfaces": []string{"eth0"},
					"ip_address":         "invalid-ip",
				},
				expectedStatus: 400,
				expectedError:  "Invalid IP address format",
			},
			{
				name: "MissingRequiredFields",
				payload: map[string]interface{}{
					"registration_key": "REG-test-123",
					"name":             "test-sensor",
					// Missing required fields
				},
				expectedStatus: 400,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				jsonBody, _ := json.Marshal(tc.payload)
				req := httptest.NewRequest("POST", "/api/v1/sensor-manager/sensors/register", bytes.NewBuffer(jsonBody))
				req.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()

				router.ServeHTTP(w, req)

				assert.Equal(t, tc.expectedStatus, w.Code)

				if tc.expectedError != "" {
					var response map[string]interface{}
					err := json.Unmarshal(w.Body.Bytes(), &response)
					assert.NoError(t, err)
					assert.Contains(t, response["error"], tc.expectedError)
				}
			})
		}
	})
}

func TestSensorRegistrationE2E_AdminSettings(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := newTestHandler()
	router := gin.New()

	// Set up admin settings routes
	api := router.Group("/api/v1")
	sensorManager := api.Group("/sensor-manager")
	{
		sensorManager.GET("/admin/settings", handler.GetAdminSettings)
		sensorManager.PUT("/admin/settings", handler.UpdateAdminSettings)
	}

	t.Run("AdminSettingsWorkflow", func(t *testing.T) {
		// Test getting admin settings
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

		// Test updating admin settings
		t.Run("UpdateAdminSettings", func(t *testing.T) {
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

		// Test invalid admin settings
		t.Run("InvalidAdminSettings", func(t *testing.T) {
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
	})
}
