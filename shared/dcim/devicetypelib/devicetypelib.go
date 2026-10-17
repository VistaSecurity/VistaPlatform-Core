// Package devicetypelib parses the NetBox community device-type library's YAML
// format (https://github.com/netbox-community/devicetype-library, CC0-1.0) into
// the device catalogue's shape (DCIM BUILD_PLAN row 2.2; ADR-0010 D4;
// DATA_MODEL §2).
//
// Two consumers share it, so a type means the same thing however it arrives:
// tools/devicetype-import, which renders the platform seed subset into
// seed.sql at build time, and inventory-service's tenant import
// (POST /dcim/device-types/import), which writes a pasted or uploaded library
// YAML as the tenant's own type.
//
// The input is UNTRUSTED data: it is decoded into typed structs (unknown keys
// are discarded structurally), bounded (document size, components per type,
// name length) and validated against the generated type registries
// (shared/dcim types_gen.go). Nothing in it is executed or fetched. A template
// whose type the registry does not know is dropped with a warning (an interface
// becomes `other` instead, as intake does), so a newer library release degrades
// rather than fails.
package devicetypelib

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
)

// Limits on untrusted input.
const (
	// MaxDocumentBytes bounds one import request (one or many documents).
	MaxDocumentBytes = 4 << 20
	// MaxDocuments bounds the documents in one request.
	MaxDocuments = 200
	// MaxComponents bounds the templates of one kind on one type (the largest
	// library chassis carry a few hundred ports).
	MaxComponents = 2048
	// MaxNameLength is the component tables' name limit.
	MaxNameLength = 64
	maxTextLength = 4096
)

// DeviceType is one library device type, normalised.
type DeviceType struct {
	Manufacturer           string
	Model                  string
	Slug                   string
	PartNumber             string
	UHeight                float64
	IsFullDepth            bool
	ExcludeFromUtilization bool
	SubdeviceRole          string
	Airflow                string
	Weight                 *float64
	WeightUnit             string
	FrontImage, RearImage  bool
	Description, Comments  string

	Interfaces         []Interface
	ConsolePorts       []Port
	ConsoleServerPorts []Port
	PowerPorts         []PowerPort
	PowerOutlets       []PowerOutlet
	FrontPorts         []FrontPort
	RearPorts          []RearPort
	ModuleBays         []ModuleBay
	DeviceBays         []DeviceBay

	// Warnings name what was dropped or adjusted, for the import result.
	Warnings []string
}

// Interface is an interface template.
type Interface struct {
	Name, Label, Type, Description string
	Enabled, MgmtOnly              bool
	PoEMode, PoEType, RFRole       string
	Bridge                         string
}

// Port is a console or console-server port template.
type Port struct {
	Name, Label, Type, Description string
}

// PowerPort is a power port template.
type PowerPort struct {
	Name, Label, Type, Description string
	MaximumDraw, AllocatedDraw     *int
}

// PowerOutlet is a power outlet template; PowerPort names a PowerPort.
type PowerOutlet struct {
	Name, Label, Type, Description string
	PowerPort, FeedLeg             string
}

// FrontPort is a front port template; RearPort names a RearPort.
type FrontPort struct {
	Name, Label, Type, Description, Color string
	RearPort                              string
	RearPortPosition                      int
}

// RearPort is a rear port template.
type RearPort struct {
	Name, Label, Type, Description, Color string
	Positions                             int
}

// ModuleBay is a module bay template.
type ModuleBay struct {
	Name, Label, Position, Description string
}

// DeviceBay is a device bay template.
type DeviceBay struct {
	Name, Label, Description string
}

// ---- the wire shape (typed: unknown keys are discarded) ------------------

type rawDoc struct {
	Manufacturer           string         `yaml:"manufacturer"`
	Model                  string         `yaml:"model"`
	Slug                   string         `yaml:"slug"`
	PartNumber             string         `yaml:"part_number"`
	UHeight                *float64       `yaml:"u_height"`
	IsFullDepth            *bool          `yaml:"is_full_depth"`
	ExcludeFromUtilization bool           `yaml:"exclude_from_utilization"`
	SubdeviceRole          string         `yaml:"subdevice_role"`
	Airflow                string         `yaml:"airflow"`
	Weight                 *float64       `yaml:"weight"`
	WeightUnit             string         `yaml:"weight_unit"`
	FrontImage             bool           `yaml:"front_image"`
	RearImage              bool           `yaml:"rear_image"`
	Description            string         `yaml:"description"`
	Comments               string         `yaml:"comments"`
	Interfaces             []rawInterface `yaml:"interfaces"`
	ConsolePorts           []rawPort      `yaml:"console-ports"`
	ConsoleServerPorts     []rawPort      `yaml:"console-server-ports"`
	PowerPorts             []rawPowerPort `yaml:"power-ports"`
	PowerOutlets           []rawOutlet    `yaml:"power-outlets"`
	FrontPorts             []rawFrontPort `yaml:"front-ports"`
	RearPorts              []rawRearPort  `yaml:"rear-ports"`
	PortMappings           []rawPortMap   `yaml:"port-mappings"`
	ModuleBays             []rawModuleBay `yaml:"module-bays"`
	DeviceBays             []rawDeviceBay `yaml:"device-bays"`
}

type rawInterface struct {
	Name        string `yaml:"name"`
	Label       string `yaml:"label"`
	Type        string `yaml:"type"`
	Description string `yaml:"description"`
	Enabled     *bool  `yaml:"enabled"`
	MgmtOnly    bool   `yaml:"mgmt_only"`
	PoEMode     string `yaml:"poe_mode"`
	PoEType     string `yaml:"poe_type"`
	RFRole      string `yaml:"rf_role"`
	Bridge      string `yaml:"bridge"`
}

type rawPort struct {
	Name        string `yaml:"name"`
	Label       string `yaml:"label"`
	Type        string `yaml:"type"`
	Description string `yaml:"description"`
}

type rawPowerPort struct {
	Name          string `yaml:"name"`
	Label         string `yaml:"label"`
	Type          string `yaml:"type"`
	Description   string `yaml:"description"`
	MaximumDraw   *int   `yaml:"maximum_draw"`
	AllocatedDraw *int   `yaml:"allocated_draw"`
}

type rawOutlet struct {
	Name        string `yaml:"name"`
	Label       string `yaml:"label"`
	Type        string `yaml:"type"`
	Description string `yaml:"description"`
	PowerPort   string `yaml:"power_port"`
	FeedLeg     string `yaml:"feed_leg"`
}

type rawFrontPort struct {
	Name        string `yaml:"name"`
	Label       string `yaml:"label"`
	Type        string `yaml:"type"`
	Description string `yaml:"description"`
	Color       string `yaml:"color"`
	// The pre-4.4 form: the mapping on the front port itself.
	RearPort         string `yaml:"rear_port"`
	RearPortPosition *int   `yaml:"rear_port_position"`
}

type rawRearPort struct {
	Name        string `yaml:"name"`
	Label       string `yaml:"label"`
	Type        string `yaml:"type"`
	Description string `yaml:"description"`
	Color       string `yaml:"color"`
	Positions   *int   `yaml:"positions"`
}

type rawPortMap struct {
	FrontPort        string `yaml:"front_port"`
	FrontPortPositon int    `yaml:"front_port_position"`
	RearPort         string `yaml:"rear_port"`
	RearPortPosition int    `yaml:"rear_port_position"`
}

type rawModuleBay struct {
	Name        string `yaml:"name"`
	Label       string `yaml:"label"`
	Position    string `yaml:"position"`
	Description string `yaml:"description"`
}

type rawDeviceBay struct {
	Name        string `yaml:"name"`
	Label       string `yaml:"label"`
	Description string `yaml:"description"`
}

// ---- parse --------------------------------------------------------------

// ErrTooLarge is input over MaxDocumentBytes or MaxDocuments.
var ErrTooLarge = errors.New("device-type library input is too large")

// Parse decodes one or more YAML documents (`---`-separated) into device
// types. A document that fails validation is an error naming its position; a
// template that cannot be stored is dropped with a warning on its type.
func Parse(data []byte) ([]DeviceType, error) {
	if len(data) > MaxDocumentBytes {
		return nil, ErrTooLarge
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var out []DeviceType
	for n := 1; ; n++ {
		var raw rawDoc
		err := dec.Decode(&raw)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("document %d: %w", n, err)
		}
		if n > MaxDocuments {
			return nil, ErrTooLarge
		}
		if raw.Manufacturer == "" && raw.Model == "" && len(raw.Interfaces) == 0 {
			continue // an empty document (a trailing `---`)
		}
		dt, err := normalise(raw)
		if err != nil {
			label := raw.Model
			if label == "" {
				label = fmt.Sprintf("document %d", n)
			}
			return nil, fmt.Errorf("%s: %w", label, err)
		}
		out = append(out, dt)
	}
	if len(out) == 0 {
		return nil, errors.New("no device type in the input")
	}
	return out, nil
}

var slugStrip = regexp.MustCompile(`[^a-z0-9]+`)

// Slugify is the catalogue's slug rule (lowercase kebab), as the API derives one.
func Slugify(s string) string {
	out := strings.Trim(slugStrip.ReplaceAllString(strings.ToLower(s), "-"), "-")
	if len(out) > 100 {
		out = strings.Trim(out[:100], "-")
	}
	return out
}

var hexColor = regexp.MustCompile(`^[0-9a-f]{6}$`)

func text(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\x00", ""))
	if len(s) > maxTextLength {
		s = s[:maxTextLength]
	}
	return s
}

func normalise(r rawDoc) (DeviceType, error) {
	dt := DeviceType{
		Manufacturer: text(r.Manufacturer), Model: text(r.Model), PartNumber: text(r.PartNumber),
		ExcludeFromUtilization: r.ExcludeFromUtilization, FrontImage: r.FrontImage, RearImage: r.RearImage,
		Description: text(r.Description), Comments: text(r.Comments), Weight: r.Weight,
		WeightUnit: strings.TrimSpace(r.WeightUnit), Airflow: strings.TrimSpace(r.Airflow),
		SubdeviceRole: strings.TrimSpace(r.SubdeviceRole), UHeight: 1, IsFullDepth: true,
	}
	if dt.Manufacturer == "" || dt.Model == "" {
		return dt, errors.New("manufacturer and model are required")
	}
	if len(dt.Manufacturer) > 100 || len(dt.Model) > 200 {
		return dt, errors.New("manufacturer or model is too long")
	}
	dt.Slug = Slugify(r.Slug)
	if dt.Slug == "" {
		dt.Slug = Slugify(dt.Model)
	}
	if dt.Slug == "" {
		return dt, errors.New("no slug can be derived from the model")
	}
	if r.UHeight != nil {
		u := *r.UHeight
		if u < 0 || u > 100 || u*2 != float64(int(u*2)) {
			return dt, fmt.Errorf("u_height %v must be a non-negative multiple of 0.5", u)
		}
		dt.UHeight = u
	}
	if r.IsFullDepth != nil {
		dt.IsFullDepth = *r.IsFullDepth
	}
	if !oneOf(dt.Airflow, "", "front-to-rear", "rear-to-front", "left-to-right", "right-to-left", "side-to-rear",
		"rear-to-side", "bottom-to-top", "top-to-bottom", "passive", "mixed") {
		dt.Warnings = append(dt.Warnings, fmt.Sprintf("airflow %q dropped", dt.Airflow))
		dt.Airflow = ""
	}
	if !oneOf(dt.SubdeviceRole, "", "parent", "child") {
		dt.Warnings = append(dt.Warnings, fmt.Sprintf("subdevice_role %q dropped", dt.SubdeviceRole))
		dt.SubdeviceRole = ""
	}
	if dt.Weight != nil && (*dt.Weight < 0 || !oneOf(dt.WeightUnit, "kg", "g", "lb", "oz")) {
		dt.Warnings = append(dt.Warnings, "weight dropped (negative, or no known unit)")
		dt.Weight, dt.WeightUnit = nil, ""
	}
	if dt.Weight == nil {
		dt.WeightUnit = ""
	}
	for _, kind := range []int{len(r.Interfaces), len(r.ConsolePorts), len(r.ConsoleServerPorts), len(r.PowerPorts),
		len(r.PowerOutlets), len(r.FrontPorts), len(r.RearPorts), len(r.ModuleBays), len(r.DeviceBays), len(r.PortMappings)} {
		if kind > MaxComponents {
			return dt, fmt.Errorf("more than %d components of one kind", MaxComponents)
		}
	}

	names := map[string]map[string]bool{}
	keep := func(kind, name string) (string, bool) {
		name = strings.TrimSpace(strings.ReplaceAll(name, "\x00", ""))
		if name == "" || len(name) > MaxNameLength {
			dt.Warnings = append(dt.Warnings, fmt.Sprintf("%s %q dropped: name must be 1-%d characters", kind, name, MaxNameLength))
			return "", false
		}
		if names[kind] == nil {
			names[kind] = map[string]bool{}
		}
		if names[kind][name] {
			dt.Warnings = append(dt.Warnings, fmt.Sprintf("%s %q dropped: duplicate name", kind, name))
			return "", false
		}
		names[kind][name] = true
		return name, true
	}

	for _, i := range r.Interfaces {
		name, ok := keep("interface", i.Name)
		if !ok {
			continue
		}
		t := strings.TrimSpace(i.Type)
		if _, ok := dcim.ParseInterfaceType(t); !ok {
			dt.Warnings = append(dt.Warnings, fmt.Sprintf("interface %q: type %q unknown, stored as other", name, t))
			t = "other"
		}
		enabled := true
		if i.Enabled != nil {
			enabled = *i.Enabled
		}
		it := Interface{Name: name, Label: text(i.Label), Type: t, Description: text(i.Description),
			Enabled: enabled, MgmtOnly: i.MgmtOnly, Bridge: strings.TrimSpace(i.Bridge)}
		if _, ok := dcim.ParsePoEMode(i.PoEMode); ok {
			it.PoEMode = i.PoEMode
		}
		if _, ok := dcim.ParsePoEType(i.PoEType); ok {
			it.PoEType = i.PoEType
		}
		if oneOf(i.RFRole, "ap", "station") {
			it.RFRole = i.RFRole
		}
		dt.Interfaces = append(dt.Interfaces, it)
	}
	consoles := func(kind string, in []rawPort) []Port {
		var out []Port
		for _, p := range in {
			name, ok := keep(kind, p.Name)
			if !ok {
				continue
			}
			t := strings.TrimSpace(p.Type)
			if _, ok := dcim.ParseConsolePortType(t); !ok && t != "" {
				dt.Warnings = append(dt.Warnings, fmt.Sprintf("%s %q: type %q unknown, left unset", kind, name, t))
				t = ""
			}
			out = append(out, Port{Name: name, Label: text(p.Label), Type: t, Description: text(p.Description)})
		}
		return out
	}
	dt.ConsolePorts = consoles("console port", r.ConsolePorts)
	dt.ConsoleServerPorts = consoles("console server port", r.ConsoleServerPorts)

	for _, p := range r.PowerPorts {
		name, ok := keep("power port", p.Name)
		if !ok {
			continue
		}
		t := strings.TrimSpace(p.Type)
		if _, ok := dcim.ParsePowerPortType(t); !ok && t != "" {
			dt.Warnings = append(dt.Warnings, fmt.Sprintf("power port %q: type %q unknown, left unset", name, t))
			t = ""
		}
		pp := PowerPort{Name: name, Label: text(p.Label), Type: t, Description: text(p.Description)}
		if p.MaximumDraw != nil && *p.MaximumDraw >= 1 {
			pp.MaximumDraw = p.MaximumDraw
		}
		if p.AllocatedDraw != nil && *p.AllocatedDraw >= 1 {
			pp.AllocatedDraw = p.AllocatedDraw
		}
		dt.PowerPorts = append(dt.PowerPorts, pp)
	}
	for _, o := range r.PowerOutlets {
		name, ok := keep("power outlet", o.Name)
		if !ok {
			continue
		}
		t := strings.TrimSpace(o.Type)
		if _, ok := dcim.ParsePowerOutletType(t); !ok && t != "" {
			dt.Warnings = append(dt.Warnings, fmt.Sprintf("power outlet %q: type %q unknown, left unset", name, t))
			t = ""
		}
		po := PowerOutlet{Name: name, Label: text(o.Label), Type: t, Description: text(o.Description)}
		if names["power port"][strings.TrimSpace(o.PowerPort)] {
			po.PowerPort = strings.TrimSpace(o.PowerPort)
		}
		if oneOf(o.FeedLeg, "A", "B", "C") {
			po.FeedLeg = o.FeedLeg
		}
		dt.PowerOutlets = append(dt.PowerOutlets, po)
	}
	for _, p := range r.RearPorts {
		name, ok := keep("rear port", p.Name)
		if !ok {
			continue
		}
		t := strings.TrimSpace(p.Type)
		if _, ok := dcim.ParsePortType(t); !ok {
			dt.Warnings = append(dt.Warnings, fmt.Sprintf("rear port %q dropped: type %q unknown", name, t))
			delete(names["rear port"], name)
			continue
		}
		pos := 1
		if p.Positions != nil && *p.Positions >= 1 && *p.Positions <= 1024 {
			pos = *p.Positions
		}
		dt.RearPorts = append(dt.RearPorts, RearPort{Name: name, Label: text(p.Label), Type: t,
			Description: text(p.Description), Color: color(p.Color), Positions: pos})
	}
	// The 4.4+ form maps front to rear in a separate list; take the first
	// mapping of each front port (our front port has one rear port, as
	// DATA_MODEL §2.4 and NetBox ≤ 4.3).
	mapping := map[string]rawPortMap{}
	for _, m := range r.PortMappings {
		if _, seen := mapping[m.FrontPort]; !seen {
			mapping[m.FrontPort] = m
		}
	}
	taken := map[string]bool{}
	for _, p := range r.FrontPorts {
		name, ok := keep("front port", p.Name)
		if !ok {
			continue
		}
		t := strings.TrimSpace(p.Type)
		if _, ok := dcim.ParsePortType(t); !ok {
			dt.Warnings = append(dt.Warnings, fmt.Sprintf("front port %q dropped: type %q unknown", name, t))
			continue
		}
		fp := FrontPort{Name: name, Label: text(p.Label), Type: t, Description: text(p.Description), Color: color(p.Color), RearPortPosition: 1}
		rear, pos := strings.TrimSpace(p.RearPort), 1
		if p.RearPortPosition != nil {
			pos = *p.RearPortPosition
		}
		if m, ok := mapping[name]; ok {
			rear, pos = strings.TrimSpace(m.RearPort), m.RearPortPosition
		}
		key := rear + "\x00" + strconv.Itoa(pos)
		if rear != "" && names["rear port"][rear] && pos >= 1 && pos <= 1024 && !taken[key] {
			fp.RearPort, fp.RearPortPosition = rear, pos
			taken[key] = true
		} else if rear != "" {
			dt.Warnings = append(dt.Warnings, fmt.Sprintf("front port %q: rear port %q position %d not mapped", name, rear, pos))
		}
		dt.FrontPorts = append(dt.FrontPorts, fp)
	}
	for _, b := range r.ModuleBays {
		name, ok := keep("module bay", b.Name)
		if !ok {
			continue
		}
		dt.ModuleBays = append(dt.ModuleBays, ModuleBay{Name: name, Label: text(b.Label), Position: text(b.Position), Description: text(b.Description)})
	}
	for _, b := range r.DeviceBays {
		name, ok := keep("device bay", b.Name)
		if !ok {
			continue
		}
		dt.DeviceBays = append(dt.DeviceBays, DeviceBay{Name: name, Label: text(b.Label), Description: text(b.Description)})
	}
	// A bridge names another interface template of the same type.
	for i := range dt.Interfaces {
		if b := dt.Interfaces[i].Bridge; b != "" && (!names["interface"][b] || b == dt.Interfaces[i].Name) {
			dt.Interfaces[i].Bridge = ""
		}
	}
	return dt, nil
}

func color(c string) string {
	c = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(c), "#"))
	if hexColor.MatchString(c) {
		return c
	}
	return ""
}

func oneOf(v string, allowed ...string) bool {
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}

// ImagePaths returns the library paths of a type's elevation images (the
// library's convention: elevation-images/<Manufacturer>/<slug>.{front,rear}.png),
// for external_ids.library; empty for an image the type says it lacks. The
// file extension is the library's usual one — the CDN fetch (off by default)
// tries it; a missing image is simply not shown.
func (d DeviceType) ImagePaths() (front, rear string) {
	base := "elevation-images/" + d.Manufacturer + "/" + d.Slug
	if d.FrontImage {
		front = base + ".front.png"
	}
	if d.RearImage {
		rear = base + ".rear.png"
	}
	return front, rear
}

// TemplateCount is the number of templates the type carries, all kinds.
func (d DeviceType) TemplateCount() int {
	return len(d.Interfaces) + len(d.ConsolePorts) + len(d.ConsoleServerPorts) + len(d.PowerPorts) +
		len(d.PowerOutlets) + len(d.FrontPorts) + len(d.RearPorts) + len(d.ModuleBays) + len(d.DeviceBays)
}
