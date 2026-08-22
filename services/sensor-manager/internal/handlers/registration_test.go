package handlers

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// handlerWithNoopLog returns a Handler with a discard logger so handlers that use h.log do not panic.
func handlerWithNoopLog() *Handler {
	h := &Handler{}
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	h.SetLogger(logger)
	return h
}

func TestCreatePendingSensor_Validation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Create a handler with nil sensor service for validation tests
	handler := &Handler{}

	router.POST("/test", func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		handler.CreatePendingSensor(c)
	})

	tests := []struct {
		name           string
		requestBody    map[string]interface{}
		expectedStatus int
		expectedError  string
	}{
		{
			name: "missing required fields",
			requestBody: map[string]interface{}{
				"name": "test-sensor",
			},
			expectedStatus: 400,
		},
		{
			name: "invalid IP address",
			requestBody: map[string]interface{}{
				"name":       "test-sensor",
				"ip_address": "invalid-ip",
				"profile":    "datacenter_host",
			},
			expectedStatus: 400,
			expectedError:  "Invalid IP address format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonBody, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest("POST", "/test", bytes.NewBuffer(jsonBody))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedError != "" {
				var response map[string]interface{}
				if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
					t.Fatalf("decoding error response failed: %v (body: %s)", err, w.Body.String())
				}
				assert.Contains(t, response["error"], tt.expectedError)
			}
		})
	}
}

func TestRegisterSensor_Validation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	handler := handlerWithNoopLog()
	router.POST("/test", handler.RegisterSensor)

	tests := []struct {
		name           string
		requestBody    map[string]interface{}
		expectedStatus int
		expectedError  string
	}{
		{
			name: "invalid IP format",
			requestBody: map[string]interface{}{
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
			name: "missing required fields",
			requestBody: map[string]interface{}{
				"registration_key": "REG-test-123",
				"name":             "test-sensor",
			},
			expectedStatus: 400,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonBody, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest("POST", "/test", bytes.NewBuffer(jsonBody))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedError != "" {
				var response map[string]interface{}
				if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
					t.Fatalf("decoding error response failed: %v (body: %s)", err, w.Body.String())
				}
				assert.Contains(t, response["error"], tt.expectedError)
			}
		})
	}
}

func TestGetPendingSensors_Validation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := &Handler{}

	tests := []struct {
		name           string
		setupContext   func(*gin.Context)
		expectedStatus int
	}{
		{
			name: "no tenant ID",
			setupContext: func(c *gin.Context) {
				// Don't set tenantID
			},
			expectedStatus: 400,
		},
		{
			name: "invalid tenant ID type",
			setupContext: func(c *gin.Context) {
				c.Set("tenantID", "invalid-uuid")
			},
			expectedStatus: 400,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.GET("/test", func(c *gin.Context) {
				tt.setupContext(c)
				handler.GetPendingSensors(c)
			})

			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

func TestDeletePendingSensor_Validation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := &Handler{}

	tests := []struct {
		name            string
		registrationKey string
		expectedStatus  int
	}{
		{
			name:            "empty key",
			registrationKey: "",
			expectedStatus:  404,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.DELETE("/test/:key", handler.DeletePendingSensor)

			req := httptest.NewRequest("DELETE", "/test/"+tt.registrationKey, nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

func TestAdminSettings(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := &Handler{}

	tests := []struct {
		name           string
		method         string
		requestBody    map[string]interface{}
		expectedStatus int
	}{
		{
			name:           "get admin settings",
			method:         "GET",
			expectedStatus: 200,
		},
		{
			name:   "update admin settings - valid",
			method: "PUT",
			requestBody: map[string]interface{}{
				"key_expiration_minutes": 120,
				"max_pending_sensors":    100,
				"require_ip_validation":  true,
			},
			expectedStatus: 200,
		},
		{
			name:   "update admin settings - invalid expiration",
			method: "PUT",
			requestBody: map[string]interface{}{
				"key_expiration_minutes": 2, // Too short
				"max_pending_sensors":    100,
				"require_ip_validation":  true,
			},
			expectedStatus: 400,
		},
		{
			name:   "update admin settings - invalid max sensors",
			method: "PUT",
			requestBody: map[string]interface{}{
				"key_expiration_minutes": 60,
				"max_pending_sensors":    0, // Too low
				"require_ip_validation":  true,
			},
			expectedStatus: 400,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			if tt.method == "GET" {
				router.GET("/test", handler.GetAdminSettings)
			} else {
				router.PUT("/test", handler.UpdateAdminSettings)
			}

			var req *http.Request
			if tt.requestBody != nil {
				jsonBody, _ := json.Marshal(tt.requestBody)
				req = httptest.NewRequest(tt.method, "/test", bytes.NewBuffer(jsonBody))
				req.Header.Set("Content-Type", "application/json")
			} else {
				req = httptest.NewRequest(tt.method, "/test", nil)
			}

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

func TestHelperFunctions(t *testing.T) {
	t.Run("getProfileFeatures", func(t *testing.T) {
		features := getProfileFeatures("datacenter_host")
		assert.NotNil(t, features)
		assert.Contains(t, features, "tls_analysis")

		features = getProfileFeatures("unknown_profile")
		assert.NotNil(t, features)
	})

	t.Run("getProfileReportingInterval", func(t *testing.T) {
		interval := getProfileReportingInterval("datacenter_host")
		assert.Greater(t, interval, 0)

		interval = getProfileReportingInterval("unknown_profile")
		assert.Greater(t, interval, 0)
	})
}
