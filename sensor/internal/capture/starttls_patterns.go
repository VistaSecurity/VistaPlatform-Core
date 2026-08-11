package capture

import (
	"bytes"
	"strings"
)

// starttlsProtocol identifies a plaintext protocol that supports STARTTLS upgrade.
type starttlsProtocol struct {
	Name  string
	Ports []int
	// Detect returns true if the buffered data contains evidence of a STARTTLS upgrade.
	// Also returns the offset where the TLS handshake begins (first 0x16 byte).
	Detect func(buf []byte) (detected bool, tlsOffset int)
}

// starttlsProtocols defines detection patterns for each supported STARTTLS protocol.
var starttlsProtocols = []starttlsProtocol{
	{
		Name:  "SMTP",
		Ports: []int{25},
		Detect: func(buf []byte) (bool, int) {
			// Look for "STARTTLS" command followed by "220 " ready response,
			// then the TLS handshake (0x16 0x03).
			upper := bytes.ToUpper(buf)
			starttlsIdx := bytes.Index(upper, []byte("STARTTLS"))
			if starttlsIdx < 0 {
				return false, 0
			}
			// Look for TLS record header after the STARTTLS exchange
			return findTLSRecord(buf, starttlsIdx)
		},
	},
	{
		Name:  "IMAP",
		Ports: []int{143},
		Detect: func(buf []byte) (bool, int) {
			// IMAP: client sends "STARTTLS" command, server responds with tagged "OK"
			upper := bytes.ToUpper(buf)
			if bytes.Index(upper, []byte("STARTTLS")) < 0 {
				return false, 0
			}
			return findTLSRecord(buf, 0)
		},
	},
	{
		Name:  "POP3",
		Ports: []int{110},
		Detect: func(buf []byte) (bool, int) {
			// POP3: client sends "STLS\r\n", server responds "+OK"
			upper := bytes.ToUpper(buf)
			if bytes.Index(upper, []byte("STLS")) < 0 {
				return false, 0
			}
			return findTLSRecord(buf, 0)
		},
	},
	{
		Name:  "PostgreSQL",
		Ports: []int{5432},
		Detect: func(buf []byte) (bool, int) {
			// PostgreSQL SSL request: 8-byte message with request code 80877103 (0x04D2162F)
			for i := 0; i+8 <= len(buf); i++ {
				// Message length (4 bytes) + SSL request code (4 bytes)
				if buf[i] == 0x00 && buf[i+1] == 0x00 && buf[i+2] == 0x00 && buf[i+3] == 0x08 &&
					buf[i+4] == 0x04 && buf[i+5] == 0xD2 && buf[i+6] == 0x16 && buf[i+7] == 0x2F {
					return findTLSRecord(buf, i+8)
				}
			}
			return false, 0
		},
	},
	{
		Name:  "MySQL",
		Ports: []int{3306},
		Detect: func(buf []byte) (bool, int) {
			// MySQL: check for SSL request packet. The CLIENT_SSL flag is bit 11 (0x0800)
			// in the capability flags. The SSL request packet starts after the server greeting.
			// Look for TLS record header after any MySQL handshake.
			return findTLSRecord(buf, 0)
		},
	},
	{
		Name:  "FTP",
		Ports: []int{21},
		Detect: func(buf []byte) (bool, int) {
			// FTP: client sends "AUTH TLS\r\n", server responds "234 "
			upper := bytes.ToUpper(buf)
			if bytes.Index(upper, []byte("AUTH TLS")) < 0 {
				return false, 0
			}
			return findTLSRecord(buf, 0)
		},
	},
	{
		Name:  "XMPP",
		Ports: []int{5222},
		Detect: func(buf []byte) (bool, int) {
			// XMPP: client sends <starttls element, server sends <proceed
			lower := strings.ToLower(string(buf))
			if !strings.Contains(lower, "<starttls") {
				return false, 0
			}
			return findTLSRecord(buf, 0)
		},
	},
	{
		Name:  "LDAP",
		Ports: []int{389},
		Detect: func(buf []byte) (bool, int) {
			// LDAP: Extended operation OID 1.3.6.1.4.1.1466.20037
			// The OID is BER-encoded as 2b 06 01 04 01 8b 3a 82 f5 25 (or similar)
			oid := []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x8b, 0x3a, 0x65}
			if bytes.Index(buf, oid) < 0 {
				return false, 0
			}
			return findTLSRecord(buf, 0)
		},
	},
}

// findTLSRecord searches for a TLS record header (0x16 0x03 0x0X) in buf starting at fromOffset.
// Returns true and the offset of the TLS record if found.
func findTLSRecord(buf []byte, fromOffset int) (bool, int) {
	for i := fromOffset; i+5 <= len(buf); i++ {
		// TLS record: ContentType 0x16 (Handshake), followed by version 0x0301-0x0304
		if buf[i] == 0x16 && buf[i+1] == 0x03 && buf[i+2] >= 0x00 && buf[i+2] <= 0x04 {
			return true, i
		}
	}
	return false, 0
}

// protocolForPort returns the STARTTLS protocol definition for the given port, or nil.
func protocolForPort(port int) *starttlsProtocol {
	for i := range starttlsProtocols {
		for _, p := range starttlsProtocols[i].Ports {
			if p == port {
				return &starttlsProtocols[i]
			}
		}
	}
	return nil
}

// portInList checks if a port is in the configured STARTTLS ports list.
func portInList(port int, ports []int) bool {
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}
