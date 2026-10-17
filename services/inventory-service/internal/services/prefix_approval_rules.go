package services

// The per-prefix auto-approval rule generator (DCIM row 1.6, ADR-0010 D3).
//
// A prefix with `auto_approve_discoveries` set stands for ONE row of
// discovery_auto_approval_rules, generated here and evaluated by
// shared/approval like any rule a person writes:
//
//	source:sensor and network.ownership:internal [and network.type:<t>] and network.prefix_id=<id>
//
// It is the rule the retired network segments generated, with the segment id
// term replaced by the prefix id — which shared/approval reads off the
// LONGEST-matching prefix of the observation's address (approval.PrefixSet),
// so a rule on a /16 does not approve an address inside a /24 carved out of
// it: the /24 is where that address is, and it has no rule.
//
// Always `source:sensor`: a prefix rule never covers cloud
// discoveries — cloud resources are approved per account (ADR-0009 D5), and
// shared/approval refuses a prefix rule naming the cloud source.
// `auto_approve_sources` does not widen it; it is carried for the NetBox and
// spreadsheet shapes and read by nothing here, exactly as the segment
// generator ignored its sources list.
//
// It runs in the prefix's own write transaction, from the IPAM engine's
// AfterWrite hook (ipam_specs.go), so a prefix and its rule cannot disagree:
// creating, editing or approving a prefix writes the rule, turning the switch
// off disables it, and deleting the prefix deletes it.

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/approval"
)

// prefixApprovalQuery renders a prefix's auto-approve setting as a query over
// the `observation` target (QUERY_LANGUAGE §8).
func prefixApprovalQuery(networkType, prefixID string) string {
	terms := []string{"source:sensor", "network.ownership:internal"}
	switch t := strings.TrimSpace(networkType); t {
	case "private", "public", "vpn", "cloud":
		terms = append(terms, "network.type:"+t)
	}
	terms = append(terms, "network.prefix_id="+prefixID)
	return strings.Join(terms, " and ")
}

// rowBool reads a boolean column of an IPAM row map.
func rowBool(row map[string]any, key string) bool {
	if row == nil {
		return false
	}
	b, _ := row[key].(bool)
	return b
}

// rowString reads a text column of an IPAM row map; "" for NULL.
func rowString(row map[string]any, key string) string {
	if row == nil || row[key] == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(row[key]))
}

// syncPrefixApprovalRule keeps the generated rule of one prefix in step with
// it. pre is nil on create, post nil on delete.
func syncPrefixApprovalRule(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, pre, post map[string]any) error {
	if !rowBool(pre, "auto_approve_discoveries") && !rowBool(post, "auto_approve_discoveries") {
		// Neither side has (or had) a rule to manage: the common case, and
		// every intake write of a measured prefix.
		return nil
	}
	row := post
	if row == nil {
		row = pre
	}
	prefixID, err := uuid.Parse(rowString(row, "id"))
	if err != nil {
		return fmt.Errorf("prefix approval rule: prefix id: %w", err)
	}

	// Which rule belongs to this prefix is read out of the rule's QUERY: one
	// predicate however it is spelled (approval.PrefixIDFromQuery).
	rows, err := tx.QueryContext(ctx, `SELECT id, query FROM discovery_auto_approval_rules WHERE tenant_id = $1`, tenant)
	if err != nil {
		return fmt.Errorf("prefix approval rule: read rules: %w", err)
	}
	var ruleID uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		var q string
		if err := rows.Scan(&id, &q); err != nil {
			_ = rows.Close()
			return err
		}
		if pid, ok := approval.PrefixIDFromQuery(q); ok && pid == prefixID && ruleID == uuid.Nil {
			ruleID = id
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}

	switch {
	case post == nil:
		if ruleID != uuid.Nil {
			if _, err := tx.ExecContext(ctx, `DELETE FROM discovery_auto_approval_rules WHERE tenant_id = $1 AND id = $2`, tenant, ruleID); err != nil {
				return fmt.Errorf("prefix approval rule: delete: %w", err)
			}
		}
		return nil
	case !rowBool(post, "auto_approve_discoveries"):
		if ruleID != uuid.Nil {
			if _, err := tx.ExecContext(ctx, `UPDATE discovery_auto_approval_rules SET is_active = false, updated_at = NOW() WHERE tenant_id = $1 AND id = $2`, tenant, ruleID); err != nil {
				return fmt.Errorf("prefix approval rule: disable: %w", err)
			}
		}
		return nil
	}

	query, err := approval.ValidateRuleQuery(prefixApprovalQuery(rowString(post, "network_type"), prefixID.String()))
	if err != nil {
		// The generator produced something the language refuses: OUR bug,
		// and writing it would store a rule nothing can evaluate. Logged
		// loudly; the prefix write itself stands.
		log.Printf("[prefix approval rule] BUG: generated query for prefix %s does not validate: %v", prefixID, err)
		return nil
	}
	cidr := rowString(post, "prefix")
	status := rowString(post, "status")
	active := status != "rejected" && status != "archived"
	name := "Auto-approve sensor discoveries: " + cidr
	description := "Auto-approve sensor discoveries whose address is in prefix " + cidr
	if ruleID != uuid.Nil {
		_, err = tx.ExecContext(ctx, `UPDATE discovery_auto_approval_rules
			SET name = $1, description = $2, query = $3, is_active = $4, updated_at = NOW()
			WHERE tenant_id = $5 AND id = $6`, name, description, query, active, tenant, ruleID)
	} else {
		_, err = tx.ExecContext(ctx, `INSERT INTO discovery_auto_approval_rules
			(tenant_id, name, description, query, is_active, created_by, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, NULL, NOW(), NOW())`, tenant, name, description, query, active)
	}
	if err != nil {
		return fmt.Errorf("prefix approval rule: write: %w", err)
	}
	return nil
}

// afterPrefixWrite is the prefix spec's AfterWrite: the utilisation cache, then
// the generated approval rule.
func afterPrefixWrite(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, pre, post map[string]any) error {
	if err := refreshAfterPrefixWrite(ctx, tx, tenant, pre, post); err != nil {
		return err
	}
	return syncPrefixApprovalRule(ctx, tx, tenant, pre, post)
}
