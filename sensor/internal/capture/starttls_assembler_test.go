package capture

import (
	"testing"
)

func TestFindTLSRecord(t *testing.T) {
	// Test with a valid TLS record header
	data := []byte{0x00, 0x00, 0x16, 0x03, 0x01, 0x00, 0x05}
	found, offset := findTLSRecord(data, 0)
	if !found {
		t.Fatal("expected to find TLS record")
	}
	if offset != 2 {
		t.Errorf("expected offset 2, got %d", offset)
	}

	// Test with no TLS record
	data = []byte{0x00, 0x01, 0x02, 0x03}
	found, _ = findTLSRecord(data, 0)
	if found {
		t.Fatal("expected no TLS record found")
	}
}

func TestSMTPSTARTTLSDetection(t *testing.T) {
	proto := protocolForPort(25)
	if proto == nil {
		t.Fatal("expected SMTP protocol for port 25")
	}
	if proto.Name != "SMTP" {
		t.Errorf("expected SMTP, got %s", proto.Name)
	}

	// Simulate SMTP STARTTLS exchange followed by TLS ClientHello
	buf := []byte("220 mail.example.com ESMTP\r\nEHLO client\r\nSTARTTLS\r\n220 Ready to start TLS\r\n")
	// Append a TLS record header
	buf = append(buf, 0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x03)

	detected, tlsOffset := proto.Detect(buf)
	if !detected {
		t.Fatal("expected SMTP STARTTLS detection")
	}
	if buf[tlsOffset] != 0x16 {
		t.Errorf("TLS offset should point to 0x16, got 0x%02x", buf[tlsOffset])
	}
}

func TestIMAPSTARTTLSDetection(t *testing.T) {
	proto := protocolForPort(143)
	if proto == nil {
		t.Fatal("expected IMAP protocol for port 143")
	}

	buf := []byte("* OK IMAP ready\r\na001 STARTTLS\r\na001 OK Begin TLS\r\n")
	buf = append(buf, 0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x03)

	detected, _ := proto.Detect(buf)
	if !detected {
		t.Fatal("expected IMAP STARTTLS detection")
	}
}

func TestPOP3STARTTLSDetection(t *testing.T) {
	proto := protocolForPort(110)
	if proto == nil {
		t.Fatal("expected POP3 protocol for port 110")
	}

	buf := []byte("+OK POP3 ready\r\nSTLS\r\n+OK Begin TLS\r\n")
	buf = append(buf, 0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x03)

	detected, _ := proto.Detect(buf)
	if !detected {
		t.Fatal("expected POP3 STARTTLS detection")
	}
}

func TestPostgreSQLSSLDetection(t *testing.T) {
	proto := protocolForPort(5432)
	if proto == nil {
		t.Fatal("expected PostgreSQL protocol for port 5432")
	}

	// PostgreSQL SSL request: length=8, code=80877103
	buf := []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xD2, 0x16, 0x2F}
	// Server responds 'S' then TLS begins
	buf = append(buf, 'S')
	buf = append(buf, 0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x03)

	detected, _ := proto.Detect(buf)
	if !detected {
		t.Fatal("expected PostgreSQL SSL detection")
	}
}

func TestFTPSTARTTLSDetection(t *testing.T) {
	proto := protocolForPort(21)
	if proto == nil {
		t.Fatal("expected FTP protocol for port 21")
	}

	buf := []byte("220 FTP ready\r\nAUTH TLS\r\n234 Proceed with negotiation\r\n")
	buf = append(buf, 0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x03)

	detected, _ := proto.Detect(buf)
	if !detected {
		t.Fatal("expected FTP STARTTLS detection")
	}
}

func TestXMPPSTARTTLSDetection(t *testing.T) {
	proto := protocolForPort(5222)
	if proto == nil {
		t.Fatal("expected XMPP protocol for port 5222")
	}

	buf := []byte("<stream:stream><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/><proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
	buf = append(buf, 0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x03)

	detected, _ := proto.Detect(buf)
	if !detected {
		t.Fatal("expected XMPP STARTTLS detection")
	}
}

func TestNoSTARTTLS(t *testing.T) {
	proto := protocolForPort(25)
	if proto == nil {
		t.Fatal("expected SMTP protocol")
	}

	// Regular SMTP without STARTTLS
	buf := []byte("220 mail.example.com ESMTP\r\nEHLO client\r\nMAIL FROM:<user@example.com>\r\n")

	detected, _ := proto.Detect(buf)
	if detected {
		t.Fatal("expected no STARTTLS detection for regular SMTP")
	}
}

func TestPortInList(t *testing.T) {
	ports := []int{25, 143, 110}
	if !portInList(25, ports) {
		t.Error("expected 25 in list")
	}
	if portInList(80, ports) {
		t.Error("expected 80 not in list")
	}
}

func TestMaxSTARTTLSConstants(t *testing.T) {
	if maxSTARTTLSPlaintextBuffer != 4096 {
		t.Errorf("expected maxSTARTTLSPlaintextBuffer=4096, got %d", maxSTARTTLSPlaintextBuffer)
	}
	if maxConcurrentSTARTTLSStreams != 1000 {
		t.Errorf("expected maxConcurrentSTARTTLSStreams=1000, got %d", maxConcurrentSTARTTLSStreams)
	}
}
