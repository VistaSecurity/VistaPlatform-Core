package capture

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"
	"time"
)

// paddedClientHello is a ClientHello carrying SNI, ALPN and a padding
// extension (type 21) of padLen bytes, standing in for a hybrid post-quantum
// key share that pushes the hello past one Initial packet.
func paddedClientHello(sni string, padLen int, alpn ...string) []byte {
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)
	body = append(body, 0x00, 0x04, 0x13, 0x01, 0x13, 0x02)
	body = append(body, 0x01, 0x00)
	var exts []byte
	add := func(typ uint16, p []byte) {
		exts = binary.BigEndian.AppendUint16(exts, typ)
		exts = binary.BigEndian.AppendUint16(exts, uint16(len(p)))
		exts = append(exts, p...)
	}
	add(0x0000, buildSNIExtension(sni))
	add(0x0010, buildALPNExtension(alpn...))
	add(0x0015, make([]byte, padLen))
	body = binary.BigEndian.AppendUint16(body, uint16(len(exts)))
	body = append(body, exts...)
	msg := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(msg, body...)
}

// encryptInitialFragments builds a client Initial carrying one CRYPTO frame
// per fragment, using the same key schedule the decryptor inverts.
func encryptInitialFragments(t *testing.T, dcid []byte, pn uint32, frags ...quicCryptoFragment) []byte {
	t.Helper()
	const version = 1
	key, iv, hp, err := deriveQUICInitialSecret(dcid, quicSaltForVersion(version))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	var plain []byte
	for _, f := range frags {
		plain = append(plain, 0x06)
		plain = binary.BigEndian.AppendUint32(plain, 0x80000000|uint32(f.offset))
		plain = binary.BigEndian.AppendUint16(plain, 0x4000|uint16(len(f.data)))
		plain = append(plain, f.data...)
	}
	plain = append(plain, make([]byte, 8)...)

	hdr := []byte{0xC3}
	hdr = binary.BigEndian.AppendUint32(hdr, version)
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, 0x00, 0x00)
	hdr = binary.BigEndian.AppendUint16(hdr, 0x4000|uint16(4+len(plain)+16))
	pnBytes := binary.BigEndian.AppendUint32(nil, pn)

	nonce := append([]byte(nil), iv...)
	for i := 0; i < 4; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	ct := gcm.Seal(nil, nonce, plain, append(append([]byte(nil), hdr...), pnBytes...))
	mask, err := computeHPMask(hp, ct[:16])
	if err != nil {
		t.Fatalf("mask: %v", err)
	}
	hdr[0] ^= mask[0] & 0x0f
	for i := range pnBytes {
		pnBytes[i] ^= mask[1+i]
	}
	return append(append(hdr, pnBytes...), ct...)
}

var testQUICFlow = quicFlowKey{srcIP: "192.0.2.10", srcPort: 40000, dstIP: "198.51.100.20", dstPort: 443}

func splitHello(t *testing.T, hello []byte, dcid []byte) (p1, p2 []byte) {
	t.Helper()
	if len(hello) < 1300 {
		t.Fatalf("hello too small to need splitting: %d", len(hello))
	}
	cut := 1000
	p1 = encryptInitialFragments(t, dcid, 0, quicCryptoFragment{0, hello[:cut]})
	p2 = encryptInitialFragments(t, dcid, 1, quicCryptoFragment{uint64(cut), hello[cut:]})
	return
}

func checkInfo(t *testing.T, info *QUICClientHelloInfo, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("expected completed hello, got %v", err)
	}
	if info.SNI != "example.com" {
		t.Errorf("SNI = %q", info.SNI)
	}
	if !reflect.DeepEqual(info.ALPNProtocols, []string{"h3"}) {
		t.Errorf("ALPN = %v", info.ALPNProtocols)
	}
	if !reflect.DeepEqual(info.JA3Input.CipherSuites, []uint16{0x1301, 0x1302}) {
		t.Errorf("ciphers = %v", info.JA3Input.CipherSuites)
	}
}

func TestQUICReassemblyTwoInitials(t *testing.T) {
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	hello := paddedClientHello("example.com", 1500, "h3")
	p1, p2 := splitHello(t, hello, dcid)

	t.Run("in order", func(t *testing.T) {
		r := newQUICReassembler(16, 16384, time.Minute)
		if _, err := decryptQUICInitialWith(r, p1, testQUICFlow); !errors.Is(err, errQUICClientHelloIncomplete) {
			t.Fatalf("first fragment: err = %v, want incomplete", err)
		}
		info, err := decryptQUICInitialWith(r, p2, testQUICFlow)
		checkInfo(t, info, err)
		if r.len() != 0 {
			t.Errorf("flow state not released: %d", r.len())
		}
	})
	t.Run("reversed", func(t *testing.T) {
		r := newQUICReassembler(16, 16384, time.Minute)
		if _, err := decryptQUICInitialWith(r, p2, testQUICFlow); !errors.Is(err, errQUICClientHelloIncomplete) {
			t.Fatalf("tail first: err = %v, want incomplete", err)
		}
		info, err := decryptQUICInitialWith(r, p1, testQUICFlow)
		checkInfo(t, info, err)
	})
	t.Run("retransmit and overlap", func(t *testing.T) {
		r := newQUICReassembler(16, 16384, time.Minute)
		for i := 0; i < 3; i++ {
			if _, err := decryptQUICInitialWith(r, p1, testQUICFlow); !errors.Is(err, errQUICClientHelloIncomplete) {
				t.Fatalf("dup %d: err = %v", i, err)
			}
		}
		// An overlapping retransmit that straddles the cut.
		ov := encryptInitialFragments(t, dcid, 2, quicCryptoFragment{900, hello[900:1200]})
		if _, err := decryptQUICInitialWith(r, ov, testQUICFlow); !errors.Is(err, errQUICClientHelloIncomplete) {
			t.Fatalf("overlap: err = %v", err)
		}
		info, err := decryptQUICInitialWith(r, p2, testQUICFlow)
		checkInfo(t, info, err)
	})
	t.Run("flows are separate", func(t *testing.T) {
		r := newQUICReassembler(16, 16384, time.Minute)
		other := testQUICFlow
		other.srcPort = 40001
		if _, err := decryptQUICInitialWith(r, p1, testQUICFlow); !errors.Is(err, errQUICClientHelloIncomplete) {
			t.Fatal(err)
		}
		if _, err := decryptQUICInitialWith(r, p2, other); !errors.Is(err, errQUICClientHelloIncomplete) {
			t.Fatalf("tail from another port must not complete the hello: %v", err)
		}
	})
}

func TestQUICReassemblySinglePacket(t *testing.T) {
	dcid := []byte{9, 9, 9, 9, 9, 9, 9, 9}
	hello := paddedClientHello("example.com", 10, "h3")
	pkt := encryptInitialFragments(t, dcid, 0, quicCryptoFragment{0, hello})
	r := newQUICReassembler(16, 16384, time.Minute)
	info, err := decryptQUICInitialWith(r, pkt, testQUICFlow)
	checkInfo(t, info, err)
	if r.len() != 0 {
		t.Errorf("single-packet hello left state behind")
	}
}

func TestQUICReassemblyBounds(t *testing.T) {
	hello := paddedClientHello("example.com", 1500, "h3")
	head := hello[:1000]

	t.Run("flow cap evicts oldest", func(t *testing.T) {
		r := newQUICReassembler(2, 16384, time.Minute)
		for i := 0; i < 3; i++ {
			k := testQUICFlow
			k.srcPort = 50000 + i
			if _, err := r.add(k, []quicCryptoFragment{{0, head}}); !errors.Is(err, errQUICClientHelloIncomplete) {
				t.Fatal(err)
			}
		}
		if r.len() != 2 {
			t.Fatalf("tracked flows = %d, want 2", r.len())
		}
		oldest := testQUICFlow
		oldest.srcPort = 50000
		if _, ok := r.flows[oldest]; ok {
			t.Error("oldest flow was not evicted")
		}
	})
	t.Run("expiry", func(t *testing.T) {
		r := newQUICReassembler(16, 16384, 5*time.Second)
		now := time.Now()
		r.now = func() time.Time { return now }
		if _, err := r.add(testQUICFlow, []quicCryptoFragment{{0, head}}); !errors.Is(err, errQUICClientHelloIncomplete) {
			t.Fatal(err)
		}
		now = now.Add(6 * time.Second)
		// The stale head is gone, so the tail alone cannot complete the hello.
		if _, err := r.add(testQUICFlow, []quicCryptoFragment{{1000, hello[1000:]}}); !errors.Is(err, errQUICClientHelloIncomplete) {
			t.Fatalf("expired head must not combine with tail: %v", err)
		}
		if r.len() != 1 {
			t.Errorf("tracked flows = %d, want 1 (the new tail)", r.len())
		}
	})
	t.Run("byte cap", func(t *testing.T) {
		r := newQUICReassembler(16, 2048, time.Minute)
		if _, err := r.add(testQUICFlow, []quicCryptoFragment{{0, head}}); !errors.Is(err, errQUICClientHelloIncomplete) {
			t.Fatal(err)
		}
		// Declared length beyond the cap drops the flow.
		if _, err := r.add(testQUICFlow, []quicCryptoFragment{{1000, make([]byte, 2000)}}); err == nil || errors.Is(err, errQUICClientHelloIncomplete) {
			t.Fatalf("oversized stream: err = %v, want hard error", err)
		}
		if r.len() != 0 {
			t.Error("oversized flow still tracked")
		}
	})
}

// Through the real parser: the first Initial of a split hello yields the
// version-only discovery, the second the enriched one.
func TestParseQUICInitialSplitClientHello(t *testing.T) {
	dcid := []byte{7, 7, 7, 7, 1, 2, 3, 4}
	p1, p2 := splitHello(t, paddedClientHello("example.com", 1500, "h3"), dcid)
	quicReassembly = newQUICReassembler(16, 16384, time.Minute)
	t.Cleanup(func() {
		quicReassembly = newQUICReassembler(quicReassemblyMaxFlows, quicReassemblyMaxFlowBytes, quicReassemblyTTL)
	})

	d1 := parseQUICInitial(p1, "192.0.2.10", "198.51.100.20", 40000, 443, "s", "eth0", true)
	if d1 == nil || d1.RawMetadata["sni_server_name"] != nil {
		t.Fatalf("first Initial: want version-only discovery, got %+v", d1)
	}
	d2 := parseQUICInitial(p2, "192.0.2.10", "198.51.100.20", 40000, 443, "s", "eth0", true)
	if d2 == nil || d2.RawMetadata["sni_server_name"] != "example.com" {
		t.Fatalf("second Initial: want SNI, got %+v", d2)
	}
	if d2.RawMetadata["ja3_hash"] == nil || d2.RawMetadata["ja4_fingerprint"] == nil {
		t.Error("missing JA3/JA4")
	}
}
