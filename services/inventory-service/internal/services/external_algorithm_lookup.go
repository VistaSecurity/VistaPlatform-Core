package services

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

type externalAlgorithmLookup interface {
	GetAlgorithmByCodeCI(string) (*Algorithm, error)
}

type externalTxAlgorithms struct {
	ctx context.Context
	tx  *sqlx.Tx
}

func (lookup externalTxAlgorithms) GetAlgorithmByCodeCI(code string) (*Algorithm, error) {
	// Numeric risk is deliberately absent: an unscored catalogue component
	// still has its own qualitative strength and must participate.
	var row Algorithm
	var strength, status sql.NullString
	var pqc sql.NullBool
	err := lookup.tx.QueryRowContext(lookup.ctx, `SELECT code,category,strength,is_pqc,pqc_standardization_status FROM algorithms WHERE UPPER(code)=UPPER($1) LIMIT 1`, code).Scan(&row.Code, &row.Category, &strength, &pqc, &status)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("external algorithm lookup: %w", err)
	}
	row.Strength, row.IsPQC, row.PQCStandardizationStatus = strength.String, pqc.Valid && pqc.Bool, status.String
	return &row, nil
}

// Keep catalogue reads on the same connection as the locked observation. An
// outer-pool lookup here deadlocks when every connection already holds a writer
// transaction (even one writer with MaxOpenConns=1).
func assessExternalCryptoTx(ctx context.Context, tx *sqlx.Tx, input models.ExternalConnectionUpsert) (string, bool, string, []string, []string) {
	assessor := &ExternalConnectionsService{algorithms: externalTxAlgorithms{ctx: ctx, tx: tx}}
	return assessor.assessCrypto(input)
}
