package services

import (
	"regexp"
	"strconv"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

// Regression tests for the certificate enrichment UPDATE builder. The
// placeholder numbering once advanced for the parameter-less SET clauses
// (data_completeness / last_data_update / updated_at), pushing the WHERE
// placeholders past the bound args — postgres then rejected EVERY enrichment
// update with "could not determine data type of parameter $N", and discovery
// imports silently dropped cert updates (found via verification).

var placeholderRe = regexp.MustCompile(`\$(\d+)`)

func maxPlaceholder(t *testing.T, query string) int {
	t.Helper()
	max := 0
	for _, m := range placeholderRe.FindAllStringSubmatch(query, -1) {
		n, err := strconv.Atoi(m[1])
		require.NoError(t, err)
		if n > max {
			max = n
		}
	}
	return max
}

func TestBuildCertificateUpdateQuery_PlaceholdersMatchArgs(t *testing.T) {
	svc := &CertificateService{}
	tenantID, certID := uuid.New(), uuid.New()

	cases := map[string]models.CertificateData{
		"no fields": {},
		"typical enrichment": {
			SubjectDN:          "CN=host.example.com",
			IssuerDN:           "CN=Example CA",
			SerialNumber:       "01:02:03",
			CommonName:         "host.example.com",
			PublicKeyAlgorithm: "RSA",
			PublicKeySize:      2048,
			SignatureAlgorithm: "SHA256-RSA",
		},
		"with PEM (derived fingerprint clause)": {
			CertificatePEM: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
			SubjectDN:      "CN=host.example.com",
		},
		"sans array": {
			SubjectAlternativeNames: []string{"a.example.com", "b.example.com"},
		},
	}

	for name, certData := range cases {
		t.Run(name, func(t *testing.T) {
			query, args := svc.buildCertificateUpdateQuery(tenantID, certID, certData)

			// Every numbered placeholder must have a bound arg, and vice versa.
			assert.Equal(t, len(args), maxPlaceholder(t, query),
				"max $N must equal len(args); a mismatch makes postgres reject the whole UPDATE\nquery: %s", query)

			// The WHERE pair is always the last two args, in (id, tenant_id) order.
			require.GreaterOrEqual(t, len(args), 2)
			assert.Equal(t, certID, args[len(args)-2])
			assert.Equal(t, tenantID, args[len(args)-1])

			// The parameter-less clauses are always present.
			assert.Contains(t, query, "data_completeness = CASE")
			assert.Contains(t, query, "last_data_update = NOW()")
			assert.Contains(t, query, "updated_at = NOW()")
		})
	}
}
