package discovery

import (
	"fmt"
	"net"
	"time"
)

func init() {
	tcpProberRegistry["SMB"] = probeSMB
}

// probeSMB sends an SMB2 NEGOTIATE Request and parses the response to discover
// signing and encryption capabilities. Ported from the sensor's active prober;
// returns the neutral ProbeResult.
func probeSMB(p *Prober, conn net.Conn, _ string, port int) (*ProbeResult, error) {
	if err := conn.SetDeadline(time.Now().Add(p.timeout)); err != nil {
		return nil, fmt.Errorf("failed to set SMB probe deadline: %w", err)
	}

	// Build SMB2 NEGOTIATE Request
	// Dialects: SMB 2.0.2, 2.1, 3.0, 3.0.2, 3.1.1
	dialects := []uint16{0x0202, 0x0210, 0x0300, 0x0302, 0x0311}

	// SMB2 NEGOTIATE Request body: StructureSize(2) + DialectCount(2) +
	// SecurityMode(2) + Reserved(2) + Capabilities(4) + ClientGuid(16) +
	// ClientStartTime(8) + Dialects(2*N)
	bodySize := 36 + 2*len(dialects)
	body := make([]byte, bodySize)
	// StructureSize = 36
	body[0] = 36
	body[1] = 0
	// DialectCount
	body[2] = byte(len(dialects))
	body[3] = 0
	// SecurityMode: signing enabled
	body[4] = 0x01
	// Dialects
	for i, d := range dialects {
		body[36+2*i] = byte(d)
		body[36+2*i+1] = byte(d >> 8)
	}

	// SMB2 header (64 bytes)
	header := make([]byte, 64)
	header[0] = 0xFE // SMB2 magic
	header[1] = 0x53
	header[2] = 0x4D
	header[3] = 0x42
	header[4] = 64 // StructureSize
	// Command = NEGOTIATE (0x0000) — already zero
	// CreditRequest = 1
	header[14] = 1

	smb2Pkt := append(header, body...)

	// NetBIOS session header: Type(0x00) + Length(3 bytes)
	nbHeader := make([]byte, 4)
	nbHeader[0] = 0x00
	pktLen := len(smb2Pkt)
	nbHeader[1] = byte(pktLen >> 16)
	nbHeader[2] = byte(pktLen >> 8)
	nbHeader[3] = byte(pktLen)

	packet := append(nbHeader, smb2Pkt...)

	if _, err := conn.Write(packet); err != nil {
		return nil, fmt.Errorf("failed to send SMB NEGOTIATE: %w", err)
	}

	// Read response
	respBuf := make([]byte, 8192)
	n, err := conn.Read(respBuf)
	if err != nil {
		return nil, fmt.Errorf("failed to read SMB response: %w", err)
	}
	resp := respBuf[:n]

	// Parse: NetBIOS(4) + SMB2 header(64) + body
	if len(resp) < 4+64+8 {
		return nil, fmt.Errorf("SMB response too short: %d bytes", len(resp))
	}
	smbResp := resp[4:] // skip NetBIOS header

	// Validate SMB2 magic
	if smbResp[0] != 0xFE || smbResp[1] != 0x53 || smbResp[2] != 0x4D || smbResp[3] != 0x42 {
		return nil, fmt.Errorf("invalid SMB2 magic in response")
	}

	respBody := smbResp[64:]
	if len(respBody) < 28 {
		return nil, fmt.Errorf("SMB NEGOTIATE response body too short")
	}

	securityMode := uint16(respBody[2]) | uint16(respBody[3])<<8
	dialectRevision := uint16(respBody[4]) | uint16(respBody[5])<<8
	capabilities := uint32(respBody[24]) | uint32(respBody[25])<<8 | uint32(respBody[26])<<16 | uint32(respBody[27])<<24

	signingEnabled := securityMode&0x01 != 0
	signingRequired := securityMode&0x02 != 0
	encryptionSupported := capabilities&0x0040 != 0

	dialectName := smbprobeDialectName(dialectRevision)

	metadata := map[string]interface{}{
		"smb_dialect":          dialectName,
		"smb_dialect_revision": dialectRevision,
		"signing_enabled":      signingEnabled,
		"signing_required":     signingRequired,
		"encryption_supported": encryptionSupported,
	}

	return &ProbeResult{
		Protocol:   "SMB",
		Port:       port,
		Confidence: 0.95,
		Metadata:   metadata,
	}, nil
}

// smbprobeDialectName maps an SMB2 dialect revision (NEGOTIATE) to a
// human-readable label. Inlined equivalent of sensor/internal/smbutil.DialectName
// so the shared package carries no sensor dependency.
func smbprobeDialectName(revision uint16) string {
	switch revision {
	case 0x0202:
		return "SMB 2.0.2"
	case 0x0210:
		return "SMB 2.1"
	case 0x0300:
		return "SMB 3.0"
	case 0x0302:
		return "SMB 3.0.2"
	case 0x0311:
		return "SMB 3.1.1"
	}
	return "SMB 2.x"
}
