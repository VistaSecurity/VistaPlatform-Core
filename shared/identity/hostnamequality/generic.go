package hostnamequality

import (
	"regexp"
	"strings"
)

// IsGeneric reports whether name is a default, factory or role name that many
// unrelated devices carry: `iphone`, `printer`, `localhost`, `android-2`
// ( B2). Two records that share only such a name are not evidence of one
// device — every phone that never had its name changed announces `iphone`.
//
// # What is judged
//
// The name is lower-cased and trimmed, one trailing dot is dropped, and one
// trailing `.local` (the mDNS domain, RFC 6762 §3) is dropped. What remains must
// be a SINGLE label to be generic: the label is then looked up in the
// dictionary below and tried against the pattern.
//
// A name with more labels than that is NOT generic. `printer.corp.example` is a
// fully qualified domain name, and an FQDN is issued by somebody who owns the
// domain to say which machine this is; that its first label is `printer` says
// nothing about whether a second `printer.corp.example` could exist. It is the
// name of a place in a namespace, not a default. The same goes for
// `printer.site-a.local`: only the mDNS suffix is stripped, and the rest is
// still a qualified name.
//
// So the answer is meant for the identifiers that are in fact ambiguous: a
// `hostname`-kind value (a short name, scoped to a segment) and a `.local`
// name (which ingest also files as a scoped hostname). Callers must not apply
// it to a value they file as an `fqdn` — and by construction such a value
// has two labels and none of them `.local`, so it answers false here anyway.
//
// # What is not judged
//
// A name the operator TYPED is never generic, whatever it says: a declared
// `printer` on a device someone created by hand is that person's statement about
// which device this is. Callers on the declared path do not call this. See
// docs in shared/identity/README.md.
//
// The tenant-frequency signal (a value carried by three or more assets in the
// tenant) is the second half of the rule and needs a database; it lives in
// identity.GenericNames, not here.
func IsGeneric(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.TrimSuffix(n, ".")
	n = strings.TrimSuffix(n, ".local")
	// No separate "is it dotted" test: every dictionary entry is one label and
	// the pattern admits no dot, so a name that still has one cannot match
	// either (pinned by TestIsGeneric_EveryDictionaryEntry and the qualified-name
	// cases in TestIsGeneric_Table).
	if _, ok := genericNames[n]; ok {
		return true
	}
	return genericPattern.MatchString(n)
}

// genericPattern is the one shape the dictionary cannot list: a phone or tablet
// family name followed by an optional separator and a number (`iphone`,
// `iphone-13`, `android 4`, `pixel7`). It deliberately allows digits ONLY:
// `bobs-iphone` and `iphone-of-sam` carry a person's name, which is exactly what
// makes a name identify one device, so they are not generic.
var genericPattern = regexp.MustCompile(`^(iphone|ipad|android|galaxy|pixel)[- ]?\d*$`)

// genericNames is the dictionary of default names. It is a map literal so a
// duplicated entry is a compile error, and each entry carries its reason: a
// name is added here because many unrelated devices announce it, and the
// comment is where the next person checks that claim before adding another.
//
// Every entry is a single label, lower case. Names with a separator variant
// (`macbook-pro` and `macbookpro`) list both because hostnames are matched
// exactly, not fuzzily.
var genericNames = map[string]struct{}{
	// Apple handhelds and computers: the factory name before an owner renames it.
	"iphone":      {}, // every iPhone that was never renamed
	"ipad":        {}, // every iPad that was never renamed
	"ipod":        {}, // every iPod touch that was never renamed
	"macbook":     {}, // stock MacBook name
	"macbookpro":  {}, // stock MacBook Pro name, no separator
	"macbook-pro": {}, // stock MacBook Pro name, hyphenated
	"macbookair":  {}, // stock MacBook Air name, no separator
	"macbook-air": {}, // stock MacBook Air name, hyphenated
	"imac":        {}, // stock iMac name
	"macintosh":   {}, // classic Mac OS default
	"mac":         {}, // bare model family
	"homepod":     {}, // stock HomePod name
	"appletv":     {}, // stock Apple TV name
	"apple-tv":    {}, // stock Apple TV name, hyphenated

	// Phones from other vendors.
	"android": {}, // Android's default hostname on many builds
	"galaxy":  {}, // Samsung Galaxy line, without a model
	"pixel":   {}, // Google Pixel line, without a model

	// Operating-system installer defaults.
	"localhost":   {}, // what a host calls itself before it is configured
	"ubuntu":      {}, // Ubuntu installer default
	"debian":      {}, // Debian installer default
	"fedora":      {}, // Fedora installer default
	"raspberrypi": {}, // Raspberry Pi OS default
	"pi":          {}, // short form of the Raspberry Pi default
	"kali":        {}, // Kali installer default
	"windows":     {}, // Windows default in several images

	// Role words: a person or a vendor named the box for what it does.
	"desktop":  {}, // role, not identity
	"laptop":   {}, // role, not identity
	"pc":       {}, // role, not identity
	"computer": {}, // role, not identity
	"printer":  {}, // role, not identity; one per floor in most offices
	"router":   {}, // role, not identity
	"gateway":  {}, // role, not identity
	"switch":   {}, // role, not identity
	"camera":   {}, // role, not identity
	"host":     {}, // role, not identity
	"server":   {}, // role, not identity
	"nas":      {}, // role, not identity

	// Consumer devices that announce their product name.
	"tv":          {}, // smart TVs from several vendors
	"roku":        {}, // Roku's default
	"firetv":      {}, // Amazon Fire TV default
	"chromecast":  {}, // Google Chromecast default
	"xbox":        {}, // Xbox default
	"playstation": {}, // PlayStation default
	"ps4":         {}, // PlayStation 4 default
	"ps5":         {}, // PlayStation 5 default
	"nintendo":    {}, // Nintendo console default
	"echo":        {}, // Amazon Echo default
	"alexa":       {}, // Amazon Alexa device default

	// Placeholders a device sends when it has no name to send.
	"unknown": {}, // an implementation's word for "no name"
	"default": {}, // an implementation's word for "unset"
	"none":    {}, // a placeholder; also refused outright by IsIdentityName
}
