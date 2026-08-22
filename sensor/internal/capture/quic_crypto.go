package capture

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"

	"golang.org/x/crypto/hkdf"
)

// QUIC v1 and v2 Initial salts per RFC 9001 §5.2 and RFC 9369
var (
	quicV1Salt = []byte{
		0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
		0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
		0xcc, 0xbb, 0x7f, 0x0a,
	}
	quicV2Salt = []byte{
		0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb,
		0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
		0xf9, 0xbd, 0x2e, 0xd9,
	}
)

// HKDF labels for QUIC Initial secret derivation
var (
	clientInLabel = []byte("client in")
	quicKeyLabel  = []byte("quic key")
	quicIVLabel   = []byte("quic iv")
	quicHPLabel   = []byte("quic hp")
)

// QUICClientHelloInfo holds the extracted TLS ClientHello data from a QUIC Initial packet.
type QUICClientHelloInfo struct {
	JA3Input      JA3Input
	ALPNProtocols []string
	SNI           string
}

// decryptQUICInitial attempts to decrypt a QUIC Initial packet and extract the TLS ClientHello.
// data is the raw UDP payload. Returns the ClientHello info or an error.
func decryptQUICInitial(data []byte) (*QUICClientHelloInfo, error) {
	if len(data) < 7 {
		return nil, errors.New("packet too short")
	}

	firstByte := data[0]
	if firstByte&0xC0 != 0xC0 || firstByte&0x30 != 0x00 {
		return nil, errors.New("not a QUIC Initial packet")
	}

	version := binary.BigEndian.Uint32(data[1:5])
	salt := quicSaltForVersion(version)
	if salt == nil {
		return nil, fmt.Errorf("unsupported QUIC version: 0x%08x", version)
	}

	offset := 5

	// DCID
	if offset >= len(data) {
		return nil, errors.New("truncated DCID length")
	}
	dcidLen := int(data[offset])
	offset++
	if offset+dcidLen > len(data) {
		return nil, errors.New("truncated DCID")
	}
	dcid := data[offset : offset+dcidLen]
	offset += dcidLen

	// SCID
	if offset >= len(data) {
		return nil, errors.New("truncated SCID length")
	}
	scidLen := int(data[offset])
	offset++
	offset += scidLen

	// Token
	if offset >= len(data) {
		return nil, errors.New("truncated token length")
	}
	tokenLen, tokenLenSize := readQUICVarInt(data, offset)
	offset += tokenLenSize + int(tokenLen)

	// Payload length
	if offset >= len(data) {
		return nil, errors.New("truncated payload length")
	}
	payloadLen, payloadLenSize := readQUICVarInt(data, offset)
	offset += payloadLenSize

	if offset+int(payloadLen) > len(data) {
		return nil, errors.New("payload extends beyond packet")
	}

	// Derive Initial secrets
	clientKey, clientIV, clientHP, err := deriveQUICInitialSecret(dcid, salt)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}

	// Header is everything up to this point
	header := make([]byte, offset)
	copy(header, data[:offset])

	payload := data[offset : offset+int(payloadLen)]

	// Remove header protection
	if len(payload) < 4+16 { // minimum for sample
		return nil, errors.New("payload too short for header protection")
	}

	// Sample starts at 4 bytes into the payload (after packet number, assuming 4-byte PN)
	sampleOffset := 4
	if sampleOffset+16 > len(payload) {
		return nil, errors.New("not enough data for HP sample")
	}
	sample := payload[sampleOffset : sampleOffset+16]

	// Compute header protection mask
	mask, err := computeHPMask(clientHP, sample)
	if err != nil {
		return nil, fmt.Errorf("HP mask computation failed: %w", err)
	}

	// Unprotect first byte
	header[0] ^= mask[0] & 0x0f // Long header: 4 bits

	// Determine packet number length from unprotected first byte
	pnLen := int(header[0]&0x03) + 1

	// Unprotect packet number bytes
	pnBytes := make([]byte, pnLen)
	for i := 0; i < pnLen; i++ {
		pnBytes[i] = payload[i] ^ mask[1+i]
	}

	// Reconstruct packet number
	var pn uint64
	for i := 0; i < pnLen; i++ {
		pn = (pn << 8) | uint64(pnBytes[i])
	}

	// Build nonce: IV XOR packet number (right-aligned)
	nonce := make([]byte, len(clientIV))
	copy(nonce, clientIV)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}

	// Rebuild the authenticated header (with unprotected bytes)
	aad := make([]byte, len(header)+pnLen)
	copy(aad, header)
	copy(aad[len(header):], pnBytes)

	// Encrypted payload starts after packet number
	ciphertext := payload[pnLen:]

	// Decrypt with AES-128-GCM
	plaintext, err := decryptAESGCM(clientKey, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decryption failed: %w", err)
	}

	// Extract CRYPTO frames from decrypted payload
	cryptoData := extractCRYPTOFrames(plaintext)
	if len(cryptoData) == 0 {
		return nil, errors.New("no CRYPTO frames found")
	}

	// Parse TLS ClientHello from CRYPTO frame data
	return parseQUICClientHello(cryptoData)
}

// quicSaltForVersion returns the HKDF salt for the given QUIC version.
func quicSaltForVersion(version uint32) []byte {
	switch version {
	case 0x00000001:
		return quicV1Salt
	case 0x6b3343cf:
		return quicV2Salt
	default:
		return nil
	}
}

// deriveQUICInitialSecret derives the client key, IV, and HP key from the DCID.
func deriveQUICInitialSecret(dcid, salt []byte) (key, iv, hp []byte, err error) {
	// Initial secret = HKDF-Extract(salt, DCID)
	h := hkdf.Extract(sha256.New, dcid, salt)

	// Client initial secret
	clientSecret, err := hkdfExpandLabel(h, clientInLabel, nil, 32)
	if err != nil {
		return nil, nil, nil, err
	}

	// Derive key (16 bytes for AES-128)
	key, err = hkdfExpandLabel(clientSecret, quicKeyLabel, nil, 16)
	if err != nil {
		return nil, nil, nil, err
	}

	// Derive IV (12 bytes)
	iv, err = hkdfExpandLabel(clientSecret, quicIVLabel, nil, 12)
	if err != nil {
		return nil, nil, nil, err
	}

	// Derive HP key (16 bytes for AES-128-ECB)
	hp, err = hkdfExpandLabel(clientSecret, quicHPLabel, nil, 16)
	if err != nil {
		return nil, nil, nil, err
	}

	return key, iv, hp, nil
}

// hkdfExpandLabel implements the TLS 1.3 HKDF-Expand-Label function.
func hkdfExpandLabel(secret, label, context []byte, length int) ([]byte, error) {
	// HkdfLabel = length(2) + "tls13 " + label(var) + context(var)
	fullLabel := append([]byte("tls13 "), label...)
	hkdfLabel := make([]byte, 2+1+len(fullLabel)+1+len(context))
	hkdfLabel[0] = byte(length >> 8)
	hkdfLabel[1] = byte(length)
	hkdfLabel[2] = byte(len(fullLabel))
	copy(hkdfLabel[3:], fullLabel)
	hkdfLabel[3+len(fullLabel)] = byte(len(context))
	if len(context) > 0 {
		copy(hkdfLabel[4+len(fullLabel):], context)
	}

	expander := hkdf.Expand(sha256.New, secret, hkdfLabel)
	out := make([]byte, length)
	if _, err := io.ReadFull(expander, out); err != nil {
		return nil, err
	}
	return out, nil
}

// computeHPMask computes the AES-ECB header protection mask.
func computeHPMask(hpKey, sample []byte) ([]byte, error) {
	block, err := aes.NewCipher(hpKey)
	if err != nil {
		return nil, err
	}
	mask := make([]byte, aes.BlockSize)
	block.Encrypt(mask, sample[:aes.BlockSize])
	return mask[:5], nil
}

// decryptAESGCM decrypts ciphertext using AES-128-GCM.
func decryptAESGCM(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aesGCM.Open(nil, nonce, ciphertext, aad)
}

// extractCRYPTOFrames extracts and concatenates CRYPTO frame data from a QUIC payload.
// CRYPTO frame type is 0x06.
func extractCRYPTOFrames(payload []byte) []byte {
	var result []byte
	offset := 0

	for offset < len(payload) {
		frameType := payload[offset]

		switch frameType {
		case 0x00: // PADDING
			offset++
			continue
		case 0x01: // PING
			offset++
			continue
		case 0x06: // CRYPTO
			offset++
			// Offset field (variable-length integer)
			if offset >= len(payload) {
				return result
			}
			_, oSize := readQUICVarInt(payload, offset)
			offset += oSize

			// Length field (variable-length integer)
			if offset >= len(payload) {
				return result
			}
			dataLen, lSize := readQUICVarInt(payload, offset)
			offset += lSize

			if offset+int(dataLen) > len(payload) {
				return result
			}
			result = append(result, payload[offset:offset+int(dataLen)]...)
			offset += int(dataLen)
		case 0x02, 0x03: // ACK (RFC 9000 §19.3) or ACK with ECN (§19.3.1)
			offset++
			// Fixed prefix: largest_acknowledged, ack_delay, ack_range_count, first_ack_range
			var ackRangeCount uint64
			for i := 0; i < 4; i++ {
				if offset >= len(payload) {
					return result
				}
				v, s := readQUICVarInt(payload, offset)
				offset += s
				if i == 2 {
					ackRangeCount = v
				}
			}
			for i := uint64(0); i < ackRangeCount; i++ {
				for j := 0; j < 2; j++ {
					if offset >= len(payload) {
						return result
					}
					_, s := readQUICVarInt(payload, offset)
					offset += s
				}
			}
			if frameType == 0x03 {
				for j := 0; j < 3; j++ {
					if offset >= len(payload) {
						return result
					}
					_, s := readQUICVarInt(payload, offset)
					offset += s
				}
			}
		default:
			// Unknown frame type — stop parsing
			return result
		}
	}

	return result
}

// parseQUICClientHello parses a TLS ClientHello from CRYPTO frame data.
// The CRYPTO frame data starts with a handshake header: type(1) + length(3) + ClientHello body.
func parseQUICClientHello(cryptoData []byte) (*QUICClientHelloInfo, error) {
	if len(cryptoData) < 4 {
		return nil, errors.New("CRYPTO data too short for handshake header")
	}

	// Handshake type must be ClientHello (0x01)
	if cryptoData[0] != 0x01 {
		return nil, fmt.Errorf("expected ClientHello (0x01), got 0x%02x", cryptoData[0])
	}

	msgLen := int(cryptoData[1])<<16 | int(cryptoData[2])<<8 | int(cryptoData[3])
	if 4+msgLen > len(cryptoData) {
		return nil, errors.New("ClientHello extends beyond CRYPTO data")
	}

	msg := cryptoData[4 : 4+msgLen]
	ja3Input, alpnProtocols, sni := ParseClientHelloJA3Fields(msg)

	log.Printf("QUIC ClientHello decrypted: SNI=%s, ciphers=%d, ALPN=%v", sni, len(ja3Input.CipherSuites), alpnProtocols)

	return &QUICClientHelloInfo{
		JA3Input:      ja3Input,
		ALPNProtocols: alpnProtocols,
		SNI:           sni,
	}, nil
}
