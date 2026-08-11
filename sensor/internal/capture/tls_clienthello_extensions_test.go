package capture

import "testing"

func TestParseServerNameExtensionBody(t *testing.T) {
	t.Parallel()
	// RFC 6066: list_len=10, entry: host_name(0), name_len=7, "example"
	body := []byte{
		0x00, 0x0a,
		0x00, 0x00, 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
	}
	if got := parseServerNameExtensionBody(body); got != "example" {
		t.Fatalf("parseServerNameExtensionBody: got %q want example", got)
	}
}

func TestParseClientHelloExtensions_SNIFirst(t *testing.T) {
	t.Parallel()
	// Two extensions: SNI then padding (ignored)
	// SNI host "badssl.com" (10 octets): list_len=13, ext_len=15
	ext := []byte{
		0x00, 0x00, // server_name
		0x00, 0x0f, // len 15
		0x00, 0x0d, // list len 13
		0x00, 0x00, 0x0a, 'b', 'a', 'd', 's', 's', 'l', '.', 'c', 'o', 'm',
		0x00, 0x15, // padding
		0x00, 0x00,
	}
	ver, sni := parseClientHelloExtensions(ext, 0, len(ext))
	if ver != "" {
		t.Errorf("unexpected tls version %q", ver)
	}
	if sni != "badssl.com" {
		t.Fatalf("SNI: got %q want badssl.com", sni)
	}
}
