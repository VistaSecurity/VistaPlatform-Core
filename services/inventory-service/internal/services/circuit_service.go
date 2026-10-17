package services

// CircuitService owns circuits (DCIM BUILD_PLAN row 4.1; ADR-0010 D8;
// DATA_MODEL §6): providers, provider accounts, provider networks, circuit
// types, circuits, circuit terminations, circuit groups and group assignments.
//
// CRUD runs on the IPAM object engine (ipam_engine.go) over circuitSpecs(), so
// a circuit object gets exactly IPAM's CRUD, change recording, RLS scoping and
// platform-row refusal.

import (
	"database/sql"
)

// CircuitService is the circuits store. It is the object engine over the
// circuit specs; List / Get / Create / Update / Delete answer ErrIPAMNotFound
// for a route that is not a circuit object.
type CircuitService struct {
	*IPAMService
}

// NewCircuitService returns the store over db (the raw pool; RLS is set per
// transaction).
func NewCircuitService(db *sql.DB) *CircuitService {
	return &CircuitService{IPAMService: newObjectEngine(db, circuitSpecs())}
}

// CircuitObjects lists every object the circuits store serves, for the
// contract tests.
func CircuitObjects() []IPAMObjectInfo {
	var out []IPAMObjectInfo
	for _, sp := range circuitSpecs() {
		info := IPAMObjectInfo{Route: sp.Route, Table: sp.Table, Kind: string(sp.Kind)}
		for _, c := range sp.Cols {
			if c.Computed {
				continue
			}
			info.Writable = append(info.Writable, c.Name)
			if c.Required {
				info.Required = append(info.Required, c.Name)
			}
		}
		out = append(out, info)
	}
	return out
}
