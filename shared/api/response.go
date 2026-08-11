// Package api provides shared API patterns (error responses, pagination) for
// consistent behavior across all services.
package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// ErrorResponse sends a standard error JSON response. Internal details are
// logged but not exposed to clients.
func ErrorResponse(c *gin.Context, status int, userMessage string, internalErr error) {
	if internalErr != nil {
		logrus.WithFields(logrus.Fields{
			"status": status,
			"path":   c.Request.URL.Path,
			"method": c.Request.Method,
		}).WithError(internalErr).Error(userMessage)
	}
	c.JSON(status, gin.H{"error": userMessage})
}

// BadRequest sends a 400 error response.
func BadRequest(c *gin.Context, msg string) {
	ErrorResponse(c, http.StatusBadRequest, msg, nil)
}

// Unauthorized sends a 401 error response.
func Unauthorized(c *gin.Context, msg string) {
	ErrorResponse(c, http.StatusUnauthorized, msg, nil)
}

// Forbidden sends a 403 error response.
func Forbidden(c *gin.Context, msg string) {
	ErrorResponse(c, http.StatusForbidden, msg, nil)
}

// NotFound sends a 404 error response.
func NotFound(c *gin.Context, msg string) {
	ErrorResponse(c, http.StatusNotFound, msg, nil)
}

// InternalError sends a 500 error response, logging the real error server-side.
func InternalError(c *gin.Context, userMessage string, err error) {
	ErrorResponse(c, http.StatusInternalServerError, userMessage, err)
}
