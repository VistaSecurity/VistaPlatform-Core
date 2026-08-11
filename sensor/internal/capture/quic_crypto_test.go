package capture

import (
	"crypto/aes"
	"crypto/cipher"
	"testing"
)

func TestQuicSaltForVersion(t *testing.T) {
	if salt := quicSaltForVersion(0x00000001); salt == nil {
		t.Error("expected salt for QUIC v1")
	}
	if salt := quicSaltForVersion(0x6b3343cf); salt == nil {
		t.Error("expected salt for QUIC v2")
	}
	if salt := quicSaltForVersion(0x12345678); salt != nil {
		t.Error("expected nil salt for unknown version")
	}
}

func TestDeriveQUICInitialSecret(t *testing.T) {
	// RFC 9001 Appendix A.1: DCID = 0x8394c8f03e515708
	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}

	key, iv, hp, err := deriveQUICInitialSecret(dcid, quicV1Salt)
	if err != nil {
		t.Fatalf("key derivation failed: %v", err)
	}

	// Key should be 16 bytes (AES-128)
	if len(key) != 16 {
		t.Errorf("expected 16-byte key, got %d", len(key))
	}
	// IV should be 12 bytes
	if len(iv) != 12 {
		t.Errorf("expected 12-byte IV, got %d", len(iv))
	}
	// HP key should be 16 bytes
	if len(hp) != 16 {
		t.Errorf("expected 16-byte HP key, got %d", len(hp))
	}

	// Verify keys are not all zeros
	allZero := true
	for _, b := range key {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("key should not be all zeros")
	}
}

func TestHkdfExpandLabel(t *testing.T) {
	// Basic test: expand should produce non-nil output of requested length
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}

	out, err := hkdfExpandLabel(secret, []byte("test label"), nil, 16)
	if err != nil {
		t.Fatalf("HKDF expand failed: %v", err)
	}
	if len(out) != 16 {
		t.Errorf("expected 16 bytes, got %d", len(out))
	}

	// Same inputs should produce same output (deterministic)
	out2, _ := hkdfExpandLabel(secret, []byte("test label"), nil, 16)
	for i := range out {
		if out[i] != out2[i] {
			t.Error("HKDF output is not deterministic")
			break
		}
	}
}

func TestComputeHPMask(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	sample := make([]byte, 16)
	for i := range sample {
		sample[i] = byte(i + 16)
	}

	mask, err := computeHPMask(key, sample)
	if err != nil {
		t.Fatalf("HP mask computation failed: %v", err)
	}
	if len(mask) != 5 {
		t.Errorf("expected 5-byte mask, got %d", len(mask))
	}
}

func TestDecryptAESGCM(t *testing.T) {
	// Encrypt then decrypt to verify round-trip
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	nonce := make([]byte, 12)
	for i := range nonce {
		nonce[i] = byte(i + 16)
	}
	plaintext := []byte("hello QUIC world")
	aad := []byte("associated data")

	// Encrypt using standard library
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher failed: %v", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM failed: %v", err)
	}
	ciphertext := aesGCM.Seal(nil, nonce, plaintext, aad)

	// Decrypt using our function
	result, err := decryptAESGCM(key, nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}
	if string(result) != string(plaintext) {
		t.Errorf("decryption mismatch: got %q, want %q", result, plaintext)
	}

	// Wrong key should fail
	badKey := make([]byte, 16)
	_, err = decryptAESGCM(badKey, nonce, ciphertext, aad)
	if err == nil {
		t.Error("expected decryption failure with wrong key")
	}
}

func TestExtractCRYPTOFrames(t *testing.T) {
	// Build a payload with PADDING + CRYPTO frame
	payload := []byte{
		0x00,                    // PADDING
		0x00,                    // PADDING
		0x06,                    // CRYPTO frame type
		0x00,                    // offset = 0 (1-byte varint)
		0x05,                    // length = 5 (1-byte varint)
		'H', 'E', 'L', 'L', 'O', // data
		0x00, // PADDING
	}

	result := extractCRYPTOFrames(payload)
	if string(result) != "HELLO" {
		t.Errorf("expected 'HELLO', got %q", string(result))
	}
}

func TestExtractCRYPTOFrames_Multiple(t *testing.T) {
	payload := []byte{
		0x06, // CRYPTO
		0x00, // offset = 0
		0x03, // length = 3
		'A', 'B', 'C',
		0x06, // CRYPTO
		0x03, // offset = 3
		0x02, // length = 2
		'D', 'E',
	}

	result := extractCRYPTOFrames(payload)
	if string(result) != "ABCDE" {
		t.Errorf("expected 'ABCDE', got %q", string(result))
	}
}

func TestExtractCRYPTOFrames_Empty(t *testing.T) {
	// No CRYPTO frames
	payload := []byte{0x00, 0x00, 0x01} // PADDING + PING
	result := extractCRYPTOFrames(payload)
	if len(result) != 0 {
		t.Errorf("expected empty result, got %d bytes", len(result))
	}
}

func TestParseQUICClientHello(t *testing.T) {
	// Build a minimal ClientHello wrapped in handshake header
	// Handshake header: type(1) + length(3) + ClientHello body
	chBody := buildMinimalClientHelloBody()

	cryptoData := []byte{
		0x01, // ClientHello type
		byte(len(chBody) >> 16), byte(len(chBody) >> 8), byte(len(chBody)),
	}
	cryptoData = append(cryptoData, chBody...)

	info, err := parseQUICClientHello(cryptoData)
	if err != nil {
		t.Fatalf("parseQUICClientHello failed: %v", err)
	}
	if info.SNI != "example.com" {
		t.Errorf("expected SNI 'example.com', got '%s'", info.SNI)
	}
	if len(info.JA3Input.CipherSuites) == 0 {
		t.Error("expected at least one cipher suite")
	}
}

func TestParseQUICClientHello_NotClientHello(t *testing.T) {
	cryptoData := []byte{0x02, 0x00, 0x00, 0x01, 0x00} // ServerHello type
	_, err := parseQUICClientHello(cryptoData)
	if err == nil {
		t.Error("expected error for non-ClientHello")
	}
}

// buildMinimalClientHelloBody creates a minimal ClientHello message body for testing.
func buildMinimalClientHelloBody() []byte {
	msg := make([]byte, 0, 200)
	// Client version: TLS 1.2 (0x0303)
	msg = append(msg, 0x03, 0x03)
	// Random: 32 bytes
	msg = append(msg, make([]byte, 32)...)
	// Session ID length: 0
	msg = append(msg, 0x00)
	// Cipher suites: length 4 (2 suites)
	msg = append(msg, 0x00, 0x04)
	msg = append(msg, 0x13, 0x01) // TLS_AES_128_GCM_SHA256
	msg = append(msg, 0x13, 0x02) // TLS_AES_256_GCM_SHA384
	// Compression: length 1, null
	msg = append(msg, 0x01, 0x00)

	// Extensions: just SNI
	sniPayload := buildSNIExtension("example.com")
	extBlock := []byte{0x00, 0x00} // SNI extension type
	extBlock = append(extBlock, byte(len(sniPayload)>>8), byte(len(sniPayload)))
	extBlock = append(extBlock, sniPayload...)

	msg = append(msg, byte(len(extBlock)>>8), byte(len(extBlock)))
	msg = append(msg, extBlock...)

	return msg
}
