package approval

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/query"
	"github.com/vistasecurity/vistaplatform/shared/query/ast"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog/registrycatalog"
	"github.com/vistasecurity/vistaplatform/shared/query/eval"
	"github.com/vistasecurity/vistaplatform/shared/query/parser"
)

// ObservationTarget is the query-language target an auto-approval rule is a
// predicate over (QUERY_LANGUAGE §4.1, §8).
const ObservationTarget = "observation"

// Observation kinds — the values [Discovery.Kind] may take, matching the
// `kind` field's closed set in the catalogue.
//
// KindHostObservation is spelled here as well as in discovery-processor's
// converter because the two ends have to agree and neither imports the other:
// the converter writes it onto the wire, this package matches rules against it.
// TestObservationKindVocabularyMatchesCatalogue pins both against the
// catalogue, which is the thing that would otherwise drift silently.
const (
	KindCrypto          = "crypto"
	KindHostObservation = "host_observation"
)

// ruleCatalog is the production query catalogue, built once.
//
// It takes the default band ladder rather than models.RiskBands, and that is
// safe here for a stated reason rather than by luck: the `observation` target
// declares NO band field. A rule cannot write `risk >= high` about a thing that
// has not been scored yet, so there is no band comparison for a ladder to get
// wrong. (shared/ may not import a service, which is why the question arises.)
var ruleCatalog = sync.OnceValue(func() *registrycatalog.Catalog {
	return query.DefaultCatalog()
})

func ruleOptions() query.Options { return query.DefaultOptionsFor(ruleCatalog()) }

// RuleEvaluator evaluates auto-approval rules against discoveries.
type RuleEvaluator struct{}

// NewRuleEvaluator creates a new rule evaluator.
func NewRuleEvaluator() *RuleEvaluator {
	return &RuleEvaluator{}
}

// ValidateRuleQuery checks a rule's query at WRITE time and returns its
// canonical form, which is what should be stored.
//
// Validating on write is the point of the change: the old jsonb interpreter
// read the keys it recognised and ignored the rest, so a misspelled condition
// produced a rule that was quietly WIDER than what the author wrote. Here a
// misspelling is a refusal with a span and a suggestion.
func ValidateRuleQuery(src string) (string, error) {
	if strings.TrimSpace(src) == "" {
		// An empty rule matches every observation. That is a real thing to
		// want (auto-approve this segment, no further conditions) and the
		// segment writer produces it, so it is not an error.
		return "", nil
	}
	node, err := query.Check(src, ObservationTarget, ruleCatalog(), ruleOptions().Validate)
	if err != nil {
		return "", err
	}
	return query.FormatNode(node), nil
}

// EvaluateRule reports whether a discovery matches the rule.
//
// The rule's AST is compiled once and cached on the Rule, so a batch of a
// thousand discoveries parses each rule once. A rule whose query does not
// validate is reported as an ERROR and never matches — failing closed, because
// the alternative is auto-approving on a rule nobody could read.
func (e *RuleEvaluator) EvaluateRule(rule *Rule, discovery Discovery, classification *Classification) (bool, error) {
	if rule == nil || !rule.IsActive {
		return false, nil
	}
	node, err := rule.ast()
	if err != nil {
		return false, err
	}
	src := observationSource{
		d:      discovery,
		c:      classification,
		source: discoverySource(discovery),
	}
	return eval.Match(node, src, eval.Options{
		Now:    time.Now().UTC(),
		Ladder: ruleCatalog().Ladder(),
	})
}

// ast compiles and caches the rule's query.
func (r *Rule) ast() (ast.Node, error) {
	if r.compiledOK {
		return r.compiled, r.compileErr
	}
	r.compiledOK = true
	if strings.TrimSpace(r.Query) == "" {
		// Nil is "matches everything" to the evaluator. See Rule.Query.
		r.compiled = nil
		return nil, nil
	}
	node, err := query.Check(r.Query, ObservationTarget, ruleCatalog(), ruleOptions().Validate)
	if err != nil {
		r.compileErr = fmt.Errorf("auto-approval rule %s (%q) does not validate: %w", r.ID, r.Name, err)
		return nil, r.compileErr
	}
	r.compiled = node
	return node, nil
}

// SegmentIDFromQuery extracts the `network.segment_id=<uuid>` term a
// segment-generated rule carries, so inventory-service can find the rule it
// owns for a segment.
//
// It reads the AST rather than matching on the query TEXT: `segment_id=X`,
// `network.segment_id = X` and `network.segment_id="X"` are the same predicate
// and a LIKE over the text would find one of them. It does not need a
// catalogue — the parser resolves nothing, and the field's written path is
// exactly what is being looked for.
func SegmentIDFromQuery(src string) (uuid.UUID, bool) {
	if strings.TrimSpace(src) == "" {
		return uuid.Nil, false
	}
	res, err := parser.Parse(src)
	if err != nil {
		return uuid.Nil, false
	}
	var found uuid.UUID
	var ok bool
	ast.Walk(res.Root, func(n ast.Node) bool {
		cmp, isCmp := n.(*ast.Compare)
		if !isCmp || ok {
			return !ok
		}
		if !strings.EqualFold(cmp.Field.Text, "network.segment_id") {
			return true
		}
		if cmp.Op != ast.OpEq && cmp.Op != ast.OpColon {
			return true
		}
		if id, err := uuid.Parse(cmp.Value.Value); err == nil {
			found, ok = id, true
			return false
		}
		return true
	})
	return found, ok
}

// discoverySource maps a discovery onto the `source` vocabulary the catalogue
// publishes for the observation target (sensor, cloud, interrogation, import,
// manual, agent).
//
// The envelope carries `discovery_method` — the public.discovery_method enum —
// not a source name, so the mapping is here rather than at each call site.
//
// # Why an unstamped envelope still reads as "sensor"
//
// This is a DEFAULT, not a measurement, and it is kept deliberately rather than
// tightened into an Unknown. The sensor pipeline is the only producer that can
// leave the envelope empty (a passive capture that recorded no method), and
// every existing segment rule says `source:sensor` — so making an unstamped
// discovery Unknown would silently stop auto-approving the exact traffic
// auto-approval was turned on for, with nothing anywhere saying so. The old
// evaluator made the same choice; the difference is that it is now written down
// as a choice.
//
// A method the enum carries but this mapping does not recognise (source_code_scan,
// whose feature was removed) yields the empty string, which IS absent: a rule
// about a source nobody can produce should match nothing rather than fall
// through to the default.
func discoverySource(d Discovery) string {
	const defaultSource = "sensor"
	if len(d.Metadata) == 0 {
		return defaultSource
	}
	var metadata map[string]any
	if err := json.Unmarshal(d.Metadata, &metadata); err != nil {
		return defaultSource
	}
	if s, ok := metadata["source"].(string); ok {
		if mapped, known := normaliseSource(s); known {
			return mapped
		}
	}
	if method, ok := metadata["discovery_method"].(string); ok {
		mapped, _ := normaliseSource(method)
		return mapped
	}
	return defaultSource
}

// normaliseSource maps a discovery_method enum value (or one of the historical
// spellings that reached the envelope) onto the catalogue's source vocabulary.
// The second return says whether the input was RECOGNISED, so an unrecognised
// value is distinguishable from one that maps to nothing.
func normaliseSource(v string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "cloud_api", "cloud_discovery", "cloud":
		return "cloud", true
	case "sensor", "sensor_discovery", "sensor_discoveries", "passive", "active", "active_scan", "pcap",
		// The sensor's own discovery_method for a passive host observation.
		// Without it the envelope's method is UNRECOGNISED, which yields the
		// empty string — absent, not "sensor" — so every existing
		// `source:sensor` segment rule would have silently stopped
		// auto-approving the passive host rows the moment they started
		// arriving, with nothing anywhere saying so. What distinguishes a host
		// observation from a crypto finding is `kind`, not `source`: both come
		// from the sensor.
		"passive_host_observation":
		return "sensor", true
	case "device_interrogation", "interrogation":
		return "interrogation", true
	case "integration", "import", "spreadsheet", "cmdb", "cmdb_sync":
		return "import", true
	case "manual":
		return "manual", true
	case "host_scan", "agent", "device_agent":
		return "agent", true
	}
	return "", false
}
