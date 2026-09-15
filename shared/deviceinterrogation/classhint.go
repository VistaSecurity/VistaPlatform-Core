package deviceinterrogation

import (
	"context"

	"github.com/vistasecurity/vistaplatform/shared/classify"
)

// Class and vendor hints (asset-inventory ADR-0004 D6).
//
// This file used to BE the rules: three flat maps of SNMP enterprise numbers,
// Cisco product-id prefixes and UniFi device types, plus four constants, all
// hand-maintained in Go and shaped like table rows because that is what they
// were waiting to become. Workstream 2.10a built the table, and they moved into
// it verbatim — standards/classification-rules.yaml, generated into both
// shared/classify's compiled-in set and the seeded classification_rules rows.
//
// What is left here is the adapter. Every function below states the EVIDENCE
// this collector has and asks the engine what it means; none of them knows a
// vendor name or a class key any more. The point of the move is that a platform
// admin can now add "this enterprise number is a Meraki" from Catalog ▸
// Classification rules without a release, and a collector picks it up.
//
// # Which engine
//
// classify.Default() — the compiled-in table. These collectors run inside the
// device agent as well as inside device-interrogation-service, and the agent
// has no database, so a curated-table lookup here would work in one runtime and
// not the other. Feeding the collectors the CURATED engine is intake's job
// (workstream 2.10b), where the proposal is assembled with everything else
// known about the asset and the service that has the table is the one doing it.
//
// # Everything here still answers "" when it does not know
//
// An unrecognised device type, product id or enterprise number produces no hint
// at all, because a wrong class is worse than an absent one: absent shows as
// unclassified, wrong shows as a fact. The engine holds that rule now — it also
// declines to answer when two rules disagree — and these wrappers pass it
// through unchanged.

// Collector platform identities, as the `platform` rules in
// standards/classification-rules.yaml spell them. They are the evidence "this
// device answered THIS management API", which is a much stronger claim than
// anything an OUI supports: FortiSwitch and FortiAP share Fortinet's OUIs but
// do not serve the FortiOS API, so the OUI rules assert only a vendor and these
// assert a class.
const (
	platformPANOS           = "panos"
	platformFortiOS         = "fortios"
	platformIControl        = "icontrol"
	platformUniFiController = "unifi_controller"
)

// classHintEngine is the rule engine these hints resolve against.
var classHintEngine = classify.Default

// platformClassHint returns the asset class a collector platform implies, or
// "". The vendor is not returned: every caller already knows it — it is the
// vendor whose API they just spoke — and returning a second opinion would only
// create a way for the two to disagree.
func platformClassHint(platform string) string {
	return classHintEngine().Classify(context.Background(), classify.ClassifyInput{
		Platform: platform,
	}).Class
}

// modelClassHint returns the asset class a vendor's model or product id
// implies, or "".
//
// The vendor is passed so the engine can scope the match: a model rule that
// names a vendor does not fire for another one, which is what lets short,
// generic prefixes ("usw") live in the table beside structured ones ("WS-C").
func modelClassHint(vendor, model string) string {
	return classHintEngine().Classify(context.Background(), classify.ClassifyInput{
		Vendor: vendor,
		Model:  model,
	}).Class
}

// panClassHint is what a device answering the PAN-OS XML API is. A Panorama
// management server is the exception, and it does not answer this API shape.
func panClassHint() string { return platformClassHint(platformPANOS) }

// fortinetClassHint is what a device answering the FortiOS API is. FortiGate is
// the only platform this interrogator supports; FortiSwitch and FortiAP are
// managed THROUGH one and are not interrogated directly, so there is no
// ambiguity to guess at.
func fortinetClassHint() string { return platformClassHint(platformFortiOS) }

// f5ClassHint is what a device answering iControl REST is. BIG-IP sells many
// modules, but the box is a load balancer in every one of them.
func f5ClassHint() string { return platformClassHint(platformIControl) }

// unifiControllerClassHint is what a UniFi controller is, for a peer reference.
func unifiControllerClassHint() string { return platformClassHint(platformUniFiController) }

// unifiClassHint returns the asset class a UniFi device type implies, or "".
// The controller's `type` is a short, stable product-family code — "uap",
// "usw", "ugw" — and it is what the controller says the device IS, so it is
// matched as a model prefix scoped to Ubiquiti.
func unifiClassHint(deviceType string) string {
	return modelClassHint(unifiVendor, deviceType)
}

// ciscoClassHintForPID returns the asset class a Cisco product id implies, or
// "". Matching is by product FAMILY PREFIX, longest first, so C9800 (a wireless
// controller) is not read as a C9000-series switch.
func ciscoClassHintForPID(pid string) string {
	return modelClassHint(ciscoVendor, pid)
}

// ciscoDeviceTypeClassHint returns the asset class the configured device_type
// implies, for a device whose chassis PID is unknown or unrecognised. It is the
// last resort in the Cisco path: an operator's label is a declaration, not a
// measurement, and the rules price it accordingly.
func ciscoDeviceTypeClassHint(deviceType string) string {
	return platformClassHint(deviceType)
}

// A pool member gets NO class hint, deliberately.
//
// It was `server` at first, on the reasoning that a member is an address and a
// port and therefore something serving traffic. But a pool member can just as
// easily be another load balancer in a tiered design, a firewall VIP, or a
// container ingress, and a pool declares NOTHING about which — it declares an
// address, a port and a monitor verdict. That is the one class proposal in this
// package that would be derived from no evidence about what the peer IS.
//
// A hint reaches Approvals as a proposal, and a plausible-looking wrong
// proposal is what gets bulk-approved. With no hint, the member lands as
// `unknown_host` until something actually measures it — an interrogation of its
// own, or an agent on it.

// snmpVendorHint is what an SNMP sysObjectID resolves to: a vendor, and a class
// where the rules have one.
//
// Class is empty where the enterprise number genuinely does not imply one —
// HP, Dell and VMware each sell servers, switches and printers under a single
// number, and guessing between them would be a fabricated fact. That judgement
// now lives in the rule rows rather than in this struct's comment, which is the
// improvement: it can be corrected without a release.
type snmpVendorHint struct {
	Vendor string
	Class  string
}

// snmpObjectIDHint resolves a sysObjectID to a vendor and class hint.
//
// The engine reads the enterprise number — the fifth arc under 1.3.6.1.4.1 —
// and any longer product-tree prefix a platform admin has added beneath it,
// longest first. A sysObjectID outside the private-enterprise arc, or from an
// enterprise no rule covers, yields an empty hint rather than a guess.
//
// Net-SNMP (8072) and UCD-SNMP (2021) are deliberately absent from the rules:
// they identify the AGENT, not the hardware it runs on, and reporting
// "Net-SNMP" as a hardware vendor would put a software package in hw.vendor and
// break the end-of-life catalogue join that key exists for.
func snmpObjectIDHint(sysObjectID string) snmpVendorHint {
	out := classHintEngine().Classify(context.Background(), classify.ClassifyInput{
		SysObjectID: sysObjectID,
	})
	return snmpVendorHint{Vendor: out.Vendor, Class: out.Class}
}
