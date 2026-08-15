package handlers

// Certificate write + search HTTP handlers (). The tenant UI's
// Certificate lens (frontend-v2/src/sections/inventory/) calls create / upload
// / update / history / search / by-issuer, but those routes were never
// registered even though CertificateService.CreateCertificate / UpdateCertificate /
// GetCertificateHistory already existed. These thin handlers wire them up.
//
// search + by-issuer reuse GetCertificates (CertificateFilters carries Search +
// Issuer); upload parses the uploaded PEM with the canonical
// certificates.ExtractCertificatesFromX509 extractor (the PEM is authoritative
// for crypto fields — uploaded metadata does not override extracted values).

import (
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	sharedapi "github.com/vistasecurity/vistaplatform/shared/api"
	sharedcerts "github.com/vistasecurity/vistaplatform/shared/certificates"
)

// certTenantID extracts the tenant UUID from the gin context, writing the
// appropriate error response and returning ok=false on failure (mirrors the
// inline pattern in the read handlers).
func certTenantID(c *gin.Context) (uuid.UUID, bool) {
	tenantID, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return uuid.Nil, false
	}
	tenantUUID, ok := tenantID.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return uuid.Nil, false
	}
	return tenantUUID, true
}

// certificateWriteRequest is the snake_case JSON body for create/update.
// models.CertificateData carries no json tags, so this DTO maps the web-ui
// Certificate shape onto it.
type certificateWriteRequest struct {
	SubjectDN               string    `json:"subject_dn"`
	IssuerDN                string    `json:"issuer_dn"`
	SerialNumber            string    `json:"serial_number"`
	CommonName              string    `json:"common_name"`
	SubjectAlternativeNames []string  `json:"subject_alternative_names"`
	NotBefore               time.Time `json:"not_before"`
	NotAfter                time.Time `json:"not_after"`
	FingerprintSHA256       string    `json:"fingerprint_sha256"`
	FingerprintSHA1         string    `json:"fingerprint_sha1"`
	CertificatePEM          string    `json:"certificate_pem"`
	PublicKeyAlgorithm      string    `json:"public_key_algorithm"`
	PublicKeySize           int       `json:"public_key_size"`
	SignatureAlgorithm      string    `json:"signature_algorithm"`
	IsSelfSigned            bool      `json:"is_self_signed"`
	IsCACertificate         bool      `json:"is_ca_certificate"`
	KeyUsage                []string  `json:"key_usage"`
	ExtendedKeyUsage        []string  `json:"extended_key_usage"`
	DataSource              string    `json:"data_source"`
	CertOwnership           string    `json:"cert_ownership"` // "internal" | "third_party" | ""
}

func (r certificateWriteRequest) toCertificateData() models.CertificateData {
	return models.CertificateData{
		SubjectDN:               r.SubjectDN,
		IssuerDN:                r.IssuerDN,
		SerialNumber:            r.SerialNumber,
		CommonName:              r.CommonName,
		SubjectAlternativeNames: r.SubjectAlternativeNames,
		NotBefore:               r.NotBefore,
		NotAfter:                r.NotAfter,
		FingerprintSHA256:       r.FingerprintSHA256,
		FingerprintSHA1:         r.FingerprintSHA1,
		CertificatePEM:          r.CertificatePEM,
		PublicKeyAlgorithm:      r.PublicKeyAlgorithm,
		PublicKeySize:           r.PublicKeySize,
		SignatureAlgorithm:      r.SignatureAlgorithm,
		IsSelfSigned:            r.IsSelfSigned,
		IsCACertificate:         r.IsCACertificate,
		KeyUsage:                r.KeyUsage,
		ExtendedKeyUsage:        r.ExtendedKeyUsage,
		DataSource:              r.DataSource,
		CertOwnership:           r.CertOwnership,
	}
}

// CreateCertificate handles POST /api/v1/inventory-service/certificates
// Manually adds a certificate from caller-supplied fields.
func (h *CertificateHandler) CreateCertificate(c *gin.Context) {
	tenantUUID, ok := certTenantID(c)
	if !ok {
		return
	}

	var req certificateWriteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	data := req.toCertificateData()
	if data.DataSource == "" {
		data.DataSource = "manual"
	}

	// The service needs a fingerprint or enough to compute one (serial + issuer).
	if data.FingerprintSHA256 == "" && (data.SerialNumber == "" || data.IssuerDN == "") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "certificate requires fingerprint_sha256 or both serial_number and issuer_dn"})
		return
	}

	certificate, err := h.certificateService.CreateCertificate(tenantUUID, data)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create certificate"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"certificate": certificate})
}

// UploadCertificate handles POST /api/v1/inventory-service/certificates/upload
// Accepts a multipart PEM file (field "certificate_file"), extracts the
// certificate fields, and stores it. The PEM is authoritative — any "metadata"
// form field does not override extracted crypto fields.
func (h *CertificateHandler) UploadCertificate(c *gin.Context) {
	tenantUUID, ok := certTenantID(c)
	if !ok {
		return
	}

	fileHeader, err := c.FormFile("certificate_file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "certificate_file is required"})
		return
	}

	f, err := fileHeader.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read uploaded file"})
		return
	}
	defer func() { _ = f.Close() }()

	raw, err := io.ReadAll(io.LimitReader(f, 1<<20)) // 1 MiB cap — certs are small
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read uploaded file"})
		return
	}

	// Parse every CERTIFICATE block in the upload (leaf + any intermediates).
	var x509certs []*x509.Certificate
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid certificate PEM"})
			return
		}
		x509certs = append(x509certs, cert)
	}
	if len(x509certs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No PEM certificate found in upload"})
		return
	}

	infos := sharedcerts.ExtractCertificatesFromX509(x509certs)
	if len(infos) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Could not extract certificate data"})
		return
	}
	data := certInfoToData(infos[0], x509certs[0])
	data.DataSource = "manual"
	// Optional ownership declared by the uploader: "internal" or "third_party".
	// Validated by the DB CHECK constraint; unknown values are silently ignored.
	if ow := c.PostForm("ownership"); ow == "internal" || ow == "third_party" {
		data.CertOwnership = ow
	}

	certificate, err := h.certificateService.CreateCertificate(tenantUUID, data)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create certificate"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"certificate": certificate})
}

// certInfoToData maps the canonical extractor output (plus the parsed leaf for
// CommonName / self-signed) onto CertificateData.
func certInfoToData(info sharedcerts.CertificateInfo, leaf *x509.Certificate) models.CertificateData {
	return models.CertificateData{
		SubjectDN:               info.SubjectDN,
		IssuerDN:                info.IssuerDN,
		SerialNumber:            info.SerialNumber,
		CommonName:              leaf.Subject.CommonName,
		SubjectAlternativeNames: info.SubjectAlternativeNames,
		NotBefore:               info.NotBefore,
		NotAfter:                info.NotAfter,
		FingerprintSHA256:       info.FingerprintSHA256,
		FingerprintSHA1:         info.FingerprintSHA1,
		CertificatePEM:          info.CertificatePEM,
		PublicKeyAlgorithm:      info.KeyAlgorithm,
		PublicKeySize:           info.KeySize,
		SignatureAlgorithm:      info.SignatureAlg,
		IsCACertificate:         info.IsCA,
		IsSelfSigned:            leaf.Subject.String() == leaf.Issuer.String(),
		KeyUsage:                info.KeyUsage,
		ExtendedKeyUsage:        info.ExtendedKeyUsage,
	}
}

// UpdateCertificate handles PUT /api/v1/inventory-service/certificates/:id
// Partial update — only non-empty fields are applied.
func (h *CertificateHandler) UpdateCertificate(c *gin.Context) {
	tenantUUID, ok := certTenantID(c)
	if !ok {
		return
	}

	certID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid certificate ID"})
		return
	}

	var req certificateWriteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	certificate, err := h.certificateService.UpdateCertificate(tenantUUID, certID, req.toCertificateData())
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Certificate not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update certificate"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"certificate": certificate})
}

// GetCertificateHistory handles GET /api/v1/inventory-service/certificates/:id/history
func (h *CertificateHandler) GetCertificateHistory(c *gin.Context) {
	tenantUUID, ok := certTenantID(c)
	if !ok {
		return
	}

	certID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid certificate ID"})
		return
	}

	history, err := h.certificateService.GetCertificateHistory(tenantUUID, certID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch certificate history"})
		return
	}
	if history == nil {
		history = []models.CertificateHistory{}
	}

	c.JSON(http.StatusOK, gin.H{"history": history})
}

// SearchCertificates handles GET /api/v1/inventory-service/certificates/search
// Free-text search (q) over the tenant's certificates, reusing GetCertificates.
func (h *CertificateHandler) SearchCertificates(c *gin.Context) {
	tenantUUID, ok := certTenantID(c)
	if !ok {
		return
	}

	pg := sharedapi.ParsePagination(c)
	filters := models.CertificateFilters{
		Page:      pg.Page,
		PageSize:  pg.PageSize,
		SortBy:    c.DefaultQuery("sort_by", "not_after"),
		SortOrder: c.DefaultQuery("sort_order", "asc"),
	}
	if q := c.Query("q"); q != "" {
		filters.Search = &q
	}
	if issuer := c.Query("issuer"); issuer != "" {
		filters.Issuer = &issuer
	}
	if algorithm := c.Query("algorithm"); algorithm != "" {
		filters.Algorithm = &algorithm
	}
	if ks := c.Query("key_size_min"); ks != "" {
		if n, err := strconv.Atoi(ks); err == nil {
			filters.KeySizeMin = &n
		}
	}
	if ed := c.Query("expiring_days"); ed != "" {
		if n, err := strconv.Atoi(ed); err == nil {
			filters.ExpiringDays = &n
		}
	}

	certificates, total, err := h.certificateService.GetCertificates(tenantUUID, filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to search certificates"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"certificates": certificates,
		"pagination":   sharedapi.BuildPaginationMeta(pg, int64(total)),
	})
}

// GetCertificatesByIssuer handles GET /api/v1/inventory-service/certificates/by-issuer/:issuer
func (h *CertificateHandler) GetCertificatesByIssuer(c *gin.Context) {
	tenantUUID, ok := certTenantID(c)
	if !ok {
		return
	}

	issuer := c.Param("issuer")
	if issuer == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Issuer DN is required"})
		return
	}

	pg := sharedapi.ParsePagination(c)
	filters := models.CertificateFilters{
		Page:      pg.Page,
		PageSize:  pg.PageSize,
		Issuer:    &issuer,
		SortBy:    c.DefaultQuery("sort_by", "not_after"),
		SortOrder: c.DefaultQuery("sort_order", "asc"),
	}

	certificates, total, err := h.certificateService.GetCertificates(tenantUUID, filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch certificates by issuer"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"certificates": certificates,
		"pagination":   sharedapi.BuildPaginationMeta(pg, int64(total)),
	})
}
