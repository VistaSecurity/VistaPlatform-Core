package services

// Intake's half of the rule-based classifier (workstream 2.10b, ADR-0004 D6).
//
// Workstream 2.10a built the rule table and the engine and wired the collectors'
// in-package class hints to it. What it deliberately did NOT do is let a
// rule-derived class reach an asset: the engine produced a proposal, and
// nothing consumed one. This file is the consumer.
//
// Three things happen here and they are different things:
//
//  1. **Evidence assembly.** Each intake path holds different evidence about
//     the same kinds of device — a finding's raw_data, a passive host
//     observation's decoded attributes, an interrogated peer's identifiers —
//     and every one of them is projected onto the SAME [classify.ClassifyInput]
//     so that one host seen two ways cannot be classified two ways.
//
//  2. **A class on a NEW asset.** The rules' answer becomes the created asset's
//     `class_key`, with `class_source_kind: rule` and a `class_source_ref`
//     naming the rule row. The asset still lands in `pending_approval` like
//     every other discovery: approving the asset approves the class with it,
//     and the history entry cites the rules, so nobody is asked the same
//     question twice.
//
//  3. **A PROPOSAL on an existing asset.** A class is not overwritten, ever.
//     ADR-0008 D3 sends a machine's proposal through Approvals, and ADR-0002 D5
//     forbids the auto-decide; a rule that changed its mind six months after
//     somebody approved a class would be a silent rewrite of the inventory.
//
// # What this never does
//
// It never turns `unknown` into a guess. The engine answers Unknown when the
// rules do not decide, INCLUDING when they decide two, and this file forwards
// that verbatim — the asset stays `unknown_host` and, for the two-answer case,
// a proposal names the classes that disagreed so the CATALOGUE can be fixed
// rather than the asset guessed at.

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/ai/seams"
	"github.com/vistasecurity/vistaplatform/shared/classify"
	"github.com/vistasecurity/vistaplatform/shared/classify/classifystore"
	"github.com/vistasecurity/vistaplatform/shared/hostobs"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/classproposal"
)

// classifier returns the rule engine over the CURATED table.
//
// Lazy and once, like identityEngine, and for the same reason: the pool is not
// necessarily usable at construction. The refresher's goroutine runs for the
// life of the process — there is nothing to cancel it with here and nothing
// that would want to, since a service that stopped reloading its rule table
// would go on classifying against whatever it read at start-up with nothing
// saying so.
func (s *AssetService) classifier() *classify.Refresher {
	s.classifyOnce.Do(func() {
		interval, fromEnv := classify.RefreshIntervalFromEnv()
		if raw := strings.TrimSpace(os.Getenv(classify.RefreshEnvVar)); raw != "" && !fromEnv {
			// An operator who typed `5` meant five minutes and got the default
			// anyway. Saying so costs one line and stops them working it out
			// from behaviour.
			log.Printf("[AssetService] classify: %s=%q is not a duration; reloading every %s",
				classify.RefreshEnvVar, raw, interval)
		}
		var repo classify.Repository
		if s.db != nil && s.db.DB != nil {
			repo = classifystore.New(s.db.DB.DB)
		}
		ctx := context.Background()
		s.classifyRef = classify.NewRefresher(ctx, repo, interval, log.Printf)
		go s.classifyRef.Run(ctx)
	})
	return s.classifyRef
}

// classEvidence is everything one intake path could assemble about what a thing
// is. It is [classify.ClassifyInput] by another name, and it exists so each
// builder can fill in what it has and hand over one value.
type classEvidence = classify.ClassifyInput

// classifyEvidence runs the rules and returns the engine's full answer,
// including the matched rules and any conflict.
//
// Explain rather than Classify: the seam's own return carries a class and a
// confidence, which is all a seam contract can promise across eight
// implementations, but a RULE-based proposal can be audited in a way a learned
// one cannot. Throwing the argument away at the seam boundary would put a class
// in the approval queue with nothing behind it, and a proposal a reviewer
// cannot audit is one they can only rubber-stamp.
func (s *AssetService) classifyEvidence(ctx context.Context, ev classEvidence) classify.ClassProposal {
	// Through the SEAM, not by naming RuleClassifier. The Classifier seam is
	// selectable and `Config{Classifier: "none"}` means "propose no class at
	// all"; a call site that constructs the implementation itself cannot honour
	// that, and a control an operator can set and nothing reads is worse than no
	// control. seams.ClassifierFor swaps this service's CURATED engine into the
	// rule-based choice and leaves any other choice alone.
	c := seams.ClassifierFor(seams.Default(), s.classifier().Engine())
	return seams.Explain(ctx, c, seams.ClassFacts(ev))
}

// applyClassProposal puts the rules' answer onto an observation about to be
// resolved, and returns the proposal so the caller can record what happened
// afterwards.
//
// It only fills a hint the builder did not already have. A class the intake
// path itself established — a cloud collector reading the provider's own
// resource type through shared/assetclass, a user picking one in the class
// picker — is a better answer than a rule's, and overwriting it would be the
// classifier arguing with a measurement.
//
// A fallback hint counts as ABSENT. `unknown_host` is what the builders write
// when they have no opinion; treating it as an opinion would mean the rules
// never got to answer at all, which is the bug this file exists to fix.
//
// # A MODEL's answer is never applied here
//
// Workstream 4.2 chained the learned classifier beneath the rules, and a class
// it proposed carries `ModelID`. That class does NOT go onto the observation,
// on a new asset or an existing one: it goes to Approvals as a proposal, every
// time, and recordClassOutcome below is what raises it. A rule is deterministic
// and cites a source, so creating an asset with its class and letting the
// asset's own approval cover it is honest; a model is neither, so the same
// shortcut would mean a machine's guess entering the inventory with nobody
// having read it — which is exactly what ADR-0008 D3 forbids and what
// TestIntegration_ClassifierModel_NeverSetsAClassOnANewAsset pins.
func (s *AssetService) applyClassProposal(ctx context.Context, obs *identity.Observation, ev classEvidence) classify.ClassProposal {
	prop := s.classifyEvidence(ctx, ev)
	classproposal.Apply(obs, prop)
	return prop
}

// The class-proposal payload, its statuses and the rules for writing one live in
// shared/identity/classproposal since workstream 4.6a.
//
// They moved because device-interrogation-service's ObservationSink raises the
// same proposals for an interrogated peer, and a second copy of "when to write
// nothing" is how a queue starts re-asking a question a reviewer has already
// answered. These aliases keep the reader in class_proposal_service.go spelled
// as it was; there is one type and one set of rules behind them.
type classProposalChanges = classproposal.Changes

const (
	classProposalKind     = classproposal.Kind
	classProposalPending  = classproposal.StatusPending
	classProposalAccepted = classproposal.StatusAccepted
	classProposalRejected = classproposal.StatusRejected
)

// ---------------------------------------------------------------------------
// Evidence, per intake path
// ---------------------------------------------------------------------------

// findingClassEvidence projects a discovery finding onto the rule inputs.
//
// Everything here is read from what the producers already write; nothing is
// derived. The cloud resource type is deliberately included even though
// findingClassHint may already have turned it into a class through
// shared/assetclass's table: the two agree by construction (the cloud_type rules
// are generated from the same vocabulary), and passing it means a resource type
// the single table does not know can still be classified by a rule an admin
// added — which is the growth path D6 asks for.
func findingClassEvidence(f IngestFinding) classEvidence {
	ev := classEvidence{
		SysObjectID:       rawDataString(f.RawData, "sysobjectid", "sys_object_id", "snmp_sysobjectid"),
		CloudResourceType: rawDataString(f.RawData, "resource_type", "cloud_resource_type"),
		Banners:           bannersFromRawData(f.RawData),
		OpenPorts:         findingOpenPorts(f),
		Vendor:            rawDataString(f.RawData, "vendor", "manufacturer", "hw_vendor"),
		Model:             rawDataString(f.RawData, "model", "product_id", "pid", "hw_model"),
		Platform:          rawDataString(f.RawData, "platform", "device_type"),
		MDNSServices:      rawDataStrings(f.RawData, "mdns_services", "services"),
		LLDPCapabilities:  rawDataStrings(f.RawData, "lldp_capabilities"),
		CDPCapabilities:   rawDataStrings(f.RawData, "cdp_capabilities"),
	}
	if mac := rawDataString(f.RawData, "mac_address", "mac"); mac != "" {
		ev.MACs = append(ev.MACs, mac)
	}
	ev.MACs = append(ev.MACs, rawDataStrings(f.RawData, "mac_addresses")...)
	ev.ENIPVendorID = rawDataInt(f.RawData, "enip_vendor_id")
	return ev
}

// bannersFromRawData assembles the Banners map in the shape
// classify.ClassifyInput documents: one LINE per probe, header name included.
//
// This is the half of the contract a producer gets wrong silently. Every
// shipped banner rule anchors on `(?i)^server:\s*…`, so a bare `nginx/1.24`
// matches nothing and nothing anywhere says so — the classifier just stops
// proposing `web_application`. A producer that stores the bare header VALUE
// under a name like `server_header` therefore has its value RENDERED back into
// the line it came from here; `banner` and `ssh_banner` are already whole lines
// as the service sent them and are passed through.
func bannersFromRawData(raw map[string]interface{}) map[string]string {
	out := map[string]string{}
	for _, key := range []string{"banner", "ssh_banner", "smtp_banner", "ftp_banner", "http_banner"} {
		if v := rawDataString(raw, key); v != "" {
			out[key] = v
		}
	}
	for _, key := range []string{"server_header", "http_server", "http_server_header"} {
		v := rawDataString(raw, key)
		if v == "" {
			continue
		}
		// Only when it is NOT already a line. A field named `server_header` is
		// the bare value by convention, but a producer that put the whole line
		// in it is the likelier mistake of the two and the renderer must not
		// punish it: `Server: Server: nginx/1.24` satisfies the anchor with the
		// word "Server", matches no rule, and reports nothing — the same silent
		// nothing the renderer exists to prevent, arriving from the other side.
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(v)), "server:") {
			out[key] = strings.TrimSpace(v)
			continue
		}
		out[key] = "Server: " + v
	}
	if nested, ok := raw["raw_metadata"].(map[string]interface{}); ok {
		for k, v := range bannersFromRawData(nested) {
			if _, taken := out[k]; !taken {
				out[k] = v
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// findingOpenPorts is every port the finding says is listening.
//
// The finding's OWN port counts. A port_profile rule needs all of its ports, and
// a scan that found 9100 on one finding and 631 on another contributes one each
// — so the profile does not match and nothing is proposed. That is a real
// limitation of classifying per finding, and it fails in the safe direction.
func findingOpenPorts(f IngestFinding) []int {
	var out []int
	if f.Port != nil && *f.Port > 0 {
		out = append(out, *f.Port)
	}
	return append(out, rawDataInts(f.RawData, "open_ports", "ports")...)
}

// ---------------------------------------------------------------------------
// Recording the outcome
// ---------------------------------------------------------------------------

// recordClassOutcome writes whatever a resolution owes the class: a proposal,
// or nothing.
//
// The decision — which of the four cases this is — is
// [classproposal.Record]'s, shared with device-interrogation-service's
// ObservationSink since workstream 4.6a. This wrapper exists so the three
// intake call sites keep reading as they did and so the ENGINE's transaction is
// what gets passed, which is the part that must not change: a proposal
// committed against an asset whose creation rolled back is a queue item
// pointing at nothing.
func (s *AssetService) recordClassOutcome(
	ctx context.Context, tx *sqlx.Tx, tenantID, assetID uuid.UUID,
	outcome identity.Outcome, prop classify.ClassProposal,
) error {
	return classproposal.Record(ctx, tx, tenantID, assetID, outcome, prop)
}

// ---------------------------------------------------------------------------
// raw_data readers
// ---------------------------------------------------------------------------
//
// RawData is map[string]interface{} that has been through JSON, so an int
// arrives as a float64 and a []string as a []any. These accept both shapes and
// answer with the zero value for anything else: a value of the wrong type is an
// ABSENT value, not an error, because the alternative is a classification that
// fails outright because one collector wrote a port list as strings.

func rawDataStrings(raw map[string]interface{}, keys ...string) []string {
	if raw == nil {
		return nil
	}
	for _, k := range keys {
		switch v := raw[k].(type) {
		case []string:
			if len(v) > 0 {
				return v
			}
		case []any:
			out := make([]string, 0, len(v))
			for _, item := range v {
				if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
					out = append(out, strings.TrimSpace(s))
				}
			}
			if len(out) > 0 {
				return out
			}
		case string:
			if s := strings.TrimSpace(v); s != "" {
				return []string{s}
			}
		}
	}
	return nil
}

func rawDataInts(raw map[string]interface{}, keys ...string) []int {
	if raw == nil {
		return nil
	}
	for _, k := range keys {
		switch v := raw[k].(type) {
		case []int:
			if len(v) > 0 {
				return v
			}
		case []any:
			out := make([]int, 0, len(v))
			for _, item := range v {
				if n, ok := numberAsInt(item); ok {
					out = append(out, n)
				}
			}
			if len(out) > 0 {
				return out
			}
		}
	}
	return nil
}

func rawDataInt(raw map[string]interface{}, keys ...string) int {
	if raw == nil {
		return 0
	}
	for _, k := range keys {
		if n, ok := numberAsInt(raw[k]); ok && n != 0 {
			return n
		}
	}
	return 0
}

func numberAsInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	case json.Number:
		i, err := n.Int64()
		return int(i), err == nil
	default:
		return 0, false
	}
}

// hostObservationClassEvidence projects a passive host observation onto the
// rule inputs.
//
// This is the path row 7 of the 2.5 note was waiting on. Everything it reads was
// already being decoded and stored — the OUI vendor, the stated model, the mDNS
// service types, the LLDP and CDP capability bits — and none of it could reach a
// class, because there was nowhere honest to record one.
//
// The locally-administered MAC is passed ANYWAY, even though the builder refuses
// to use it as an identifier. The two are different questions: it is not a
// stable KEY (the device rotates it, so an asset keyed on it is a new asset per
// rotation), but the OUI half of it still says what minted the address —
// `02:42:AC` is Docker's, `52:54:00` is QEMU's, `FA:16:3E` is OpenStack's — and
// those are precisely the prefixes whose rules carry a class.
func hostObservationClassEvidence(ho *hostobs.HostObservation) classEvidence {
	if ho == nil {
		return classEvidence{}
	}
	ev := classEvidence{
		Vendor:       strings.TrimSpace(ho.Vendor),
		Model:        strings.TrimSpace(ho.Model),
		MDNSServices: ho.Services,
	}
	if mac := strings.TrimSpace(ho.MAC); mac != "" {
		ev.MACs = append(ev.MACs, mac)
	}
	ev.LLDPCapabilities = attributeStrings(ho.Attributes, "lldp_capabilities")
	ev.CDPCapabilities = attributeStrings(ho.Attributes, "cdp_capabilities")
	return ev
}

// attributeStrings reads a decoder attribute holding a list of names, accepting
// both the native []string and the []any a JSON round trip produces. The
// payload crosses two service boundaries as JSON before it gets here, so the
// native shape alone would read nothing in production and everything in a unit
// test.
func attributeStrings(attrs map[string]any, key string) []string {
	if attrs == nil {
		return nil
	}
	switch v := attrs[key].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	default:
		return nil
	}
}

// manualClassEvidence projects a declared or imported asset onto the rule
// inputs.
//
// Thin on purpose. A person filling in the asset form is not describing
// evidence, they are making an assertion, and the one thing they supply that a
// rule can key on is a MAC address — which is also the one thing a spreadsheet
// import reliably carries. Everything the rules could otherwise use (a banner,
// an open port, an advertised service) is something the platform MEASURES, and
// a declaration that claimed to have measured it would be the fabricated
// provenance this whole slice is about.
//
// It runs at all because a tenant CAN leave the class blank — an import with no
// class column, a form submitted before the picker was touched — and
// `unknown_host` where an OUI rule could have said `printer` is a worse answer
// for no reason.
func manualClassEvidence(in models.AssetInput) classEvidence {
	var ev classEvidence
	for _, id := range in.Identifiers {
		if strings.EqualFold(strings.TrimSpace(id.Kind), string(identity.KindMACAddress)) {
			if v := strings.TrimSpace(id.Value); v != "" {
				ev.MACs = append(ev.MACs, v)
			}
		}
	}
	return ev
}
