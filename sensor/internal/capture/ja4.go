package capture

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// ComputeJA4 computes the JA4 fingerprint from ClientHello fields.
// JA4 format: <protocol><version><sni><cipherCount><extCount><alpn>_<sortedCiphers>_<sortedExtensions+sigAlgs>
// The JA4 "a" section is a human-readable prefix; the "b" and "c" sections are truncated SHA256 hashes.
func ComputeJA4(input JA3Input, alpnProtocols []string, hasSNI bool) string {
	// Section a: t<version><sni><cipherCount><extCount><alpn>
	// Protocol indicator: "t" = TCP (TLS), "q" = QUIC
	proto := "t"

	// TLS version from supported_versions if available, else wire version
	ver := ja4TLSVersion(input.TLSVersion)

	// SNI indicator
	sniChar := "i" // no SNI
	if hasSNI {
		sniChar = "d" // domain present
	}

	// Filter GREASE
	ciphers := filterGREASE16(input.CipherSuites)
	extensions := filterGREASE16(input.Extensions)

	// Cipher count (2 digits, capped at 99)
	cipherCount := len(ciphers)
	if cipherCount > 99 {
		cipherCount = 99
	}

	// Extension count (2 digits, capped at 99)
	// Exclude SNI (0x0000) and ALPN (0x0010) from count per JA4 spec
	extCountFiltered := 0
	for _, e := range extensions {
		if e != 0x0000 && e != 0x0010 {
			extCountFiltered++
		}
	}
	if extCountFiltered > 99 {
		extCountFiltered = 99
	}

	// First ALPN value (first 2 chars, or "00" if none)
	alpnStr := "00"
	if len(alpnProtocols) > 0 && len(alpnProtocols[0]) >= 2 {
		alpnStr = alpnProtocols[0][:2]
	} else if len(alpnProtocols) > 0 && len(alpnProtocols[0]) == 1 {
		alpnStr = alpnProtocols[0] + "0"
	}

	sectionA := fmt.Sprintf("%s%s%s%02d%02d%s", proto, ver, sniChar, cipherCount, extCountFiltered, alpnStr)

	// Section b: sorted cipher suites (excluding GREASE), SHA256 truncated to 12 hex chars
	sortedCiphers := make([]uint16, len(ciphers))
	copy(sortedCiphers, ciphers)
	sort.Slice(sortedCiphers, func(i, j int) bool { return sortedCiphers[i] < sortedCiphers[j] })
	cipherStrs := make([]string, len(sortedCiphers))
	for i, c := range sortedCiphers {
		cipherStrs[i] = fmt.Sprintf("%04x", c)
	}
	sectionB := truncSHA256(strings.Join(cipherStrs, ","), 12)

	// Section c: sorted extensions (excluding GREASE, SNI, ALPN) + signature algorithms
	var filteredExts []uint16
	for _, e := range extensions {
		if e != 0x0000 && e != 0x0010 {
			filteredExts = append(filteredExts, e)
		}
	}
	sort.Slice(filteredExts, func(i, j int) bool { return filteredExts[i] < filteredExts[j] })
	extStrs := make([]string, len(filteredExts))
	for i, e := range filteredExts {
		extStrs[i] = fmt.Sprintf("%04x", e)
	}
	sectionC := truncSHA256(strings.Join(extStrs, ","), 12)

	return sectionA + "_" + sectionB + "_" + sectionC
}

// ComputeJA4QUIC computes JA4 with QUIC protocol indicator "q".
func ComputeJA4QUIC(input JA3Input, alpnProtocols []string, hasSNI bool) string {
	ja4 := ComputeJA4(input, alpnProtocols, hasSNI)
	// Replace the first character from "t" to "q"
	if len(ja4) > 0 {
		return "q" + ja4[1:]
	}
	return ja4
}

// ja4TLSVersion maps wire version to JA4 version string.
func ja4TLSVersion(ver uint16) string {
	switch ver {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3" // SSL 3.0
	default:
		return "00"
	}
}

// truncSHA256 computes SHA256 of input and returns the first n hex characters.
func truncSHA256(input string, n int) string {
	sum := sha256.Sum256([]byte(input))
	full := hex.EncodeToString(sum[:])
	if n > len(full) {
		return full
	}
	return full[:n]
}
