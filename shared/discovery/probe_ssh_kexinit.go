package discovery

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/cryptoparse"
)

// SSH_MSG_KEXINIT capture — the server's own algorithm offer, read off the
// wire before any key exchange happens.
//
// # Why this is hand-rolled rather than done with golang.org/x/crypto/ssh
//
// x/crypto/ssh completes the key exchange and exposes the host key, but it
// does NOT expose either side's SSH_MSG_KEXINIT name-lists — there is no
// public API for them, and the negotiated cipher/MAC/kex are internal to the
// handshake. So the probe could report which host key a server presented and
// nothing at all about what it offers: no kex algorithms, no ciphers, no MACs.
// That is precisely the data an SSH inventory exists to hold, and its absence
// left every actively-probed SSH configuration with no key_exchange_algorithm,
// no symmetric_encryption and no hash_algorithm, hence catalogue risk 0 —
// "not assessed" — however badly the server was configured.
//
// KEXINIT arrives BEFORE any key exchange, in cleartext, and reading it
// requires only the binary packet protocol (RFC 4253 §6) with no cipher, no
// MAC and no compression in effect. That is the whole of what is implemented
// here. The exchange stops at KEXINIT: no SSH_MSG_KEX_ECDH_INIT is sent, no
// keys are derived, no NEWKEYS is sent and no authentication is attempted, so
// the probe never possesses key material of any kind. The host key type and
// its fingerprint — posture, not material — still come from the x/crypto
// handshake in probe_ssh.go.
//
// Pure standard library plus shared/cryptoparse, because the standalone
// sensor cross-compiles this package with CGO disabled.

// sshMsgKexInit is the SSH_MSG_KEXINIT message number (RFC 4253 §12).
const sshMsgKexInit byte = 20

const (
	// sshMaxPacketLen bounds a binary-protocol packet. RFC 4253 §6 requires
	// every implementation to accept at least 35000 bytes and says nothing
	// larger need be honoured, so a longer packet is a malformed or hostile
	// peer rather than a real SSH server, and is refused instead of allocated.
	sshMaxPacketLen = 35000

	// sshMaxPreambleBytes bounds the free text a server may send before its
	// identification string (RFC 4253 §4.2 permits any number of such lines).
	// Unbounded, a peer that never sends "SSH-" would stream until the probe
	// deadline. The lines themselves are discarded, never stored.
	sshMaxPreambleBytes = 8192

	// sshMaxPreambleLines bounds the same preamble by line count, so a peer
	// dribbling one byte per line cannot hold the reader open.
	sshMaxPreambleLines = 64

	// sshMaxTransportPackets bounds how many packets are read while waiting
	// for the server's KEXINIT. A server may legitimately send SSH_MSG_IGNORE
	// or SSH_MSG_DEBUG first; it may not send an unbounded stream of them.
	sshMaxTransportPackets = 8

	// sshNameListFields is the number of name-lists in a KEXINIT payload
	// (RFC 4253 §7.1): kex, host key, encryption ×2, MAC ×2, compression ×2,
	// languages ×2.
	sshNameListFields = 10

	// sshMinPadding is RFC 4253 §6's minimum padding, enforced in both
	// directions — sshWrapPacket never emits less, sshReadPacket never
	// accepts less.
	sshMinPadding = 4
)

// sshClientIdentification is the identification string the probe sends. It
// names the product so an operator reading their sshd log can tell what
// connected, and declares protoversion 2.0 — the probe does not speak SSH-1,
// and claiming 1.99 would invite a server to answer in a protocol it cannot
// parse.
const sshClientIdentification = "SSH-2.0-VistaPlatform_Discovery"

// sshProbeOffer is the algorithm offer the probe puts on the wire, ordered
// STRONGEST FIRST within each list.
//
// The ordering is the load-bearing part. RFC 4253 §7.1 resolves negotiation
// to "the first algorithm on the client's name-list that is also on the
// server's name-list", so the order here decides what
// cryptoparse.NegotiateSSHAlgorithm reports as negotiated. Strong-first means
// the recorded choice is what this server would agree with a well-configured
// modern client — the honest reading of "what does this server negotiate".
//
// The lists are also deliberately BROAD, reaching down to
// diffie-hellman-group1-sha1, 3des-cbc and hmac-md5. Those entries are never
// selected against a server that offers anything better (they are last), but
// without them a legacy-only appliance — the single most interesting thing an
// SSH audit can find — would share no algorithm with the probe at all. That
// is not hypothetical: it is why the x/crypto handshake in probe_ssh.go has a
// banner-only fallback for "no common algorithm". Reading KEXINIT needs no
// common algorithm whatsoever, so the offer costs nothing and buys the weak
// server's full inventory.
var sshProbeOffer = struct {
	Kex         []string
	HostKey     []string
	Encryption  []string
	MAC         []string
	Compression []string
}{
	Kex: []string{
		"mlkem768x25519-sha256",
		"mlkem768nistp256-sha256",
		"sntrup761x25519-sha512@openssh.com",
		"sntrup761x25519-sha512",
		"curve448-sha512",
		"curve25519-sha256",
		"curve25519-sha256@libssh.org",
		"ecdh-sha2-nistp521",
		"ecdh-sha2-nistp384",
		"ecdh-sha2-nistp256",
		"diffie-hellman-group18-sha512",
		"diffie-hellman-group16-sha512",
		"diffie-hellman-group-exchange-sha256",
		"diffie-hellman-group14-sha256",
		"diffie-hellman-group14-sha1",
		"diffie-hellman-group-exchange-sha1",
		"diffie-hellman-group1-sha1",
	},
	HostKey: []string{
		"ssh-ed25519",
		"ecdsa-sha2-nistp521",
		"ecdsa-sha2-nistp384",
		"ecdsa-sha2-nistp256",
		"rsa-sha2-512",
		"rsa-sha2-256",
		"ssh-rsa",
		"ssh-dss",
	},
	Encryption: []string{
		"chacha20-poly1305@openssh.com",
		"aes256-gcm@openssh.com",
		"aes128-gcm@openssh.com",
		"aes256-ctr",
		"aes192-ctr",
		"aes128-ctr",
		"aes256-cbc",
		"aes192-cbc",
		"aes128-cbc",
		"3des-cbc",
		"arcfour256",
		"arcfour128",
		"arcfour",
	},
	MAC: []string{
		"hmac-sha2-512-etm@openssh.com",
		"hmac-sha2-256-etm@openssh.com",
		"umac-128-etm@openssh.com",
		"hmac-sha2-512",
		"hmac-sha2-256",
		"umac-128@openssh.com",
		"umac-64-etm@openssh.com",
		"umac-64@openssh.com",
		"hmac-sha1-etm@openssh.com",
		"hmac-sha1",
		"hmac-sha1-96-etm@openssh.com",
		"hmac-sha1-96",
		"hmac-md5-etm@openssh.com",
		"hmac-md5",
		"hmac-md5-96",
	},
	Compression: []string{
		"none",
		"zlib@openssh.com",
		"zlib",
	},
}

// sshKexInitCapture is everything the KEXINIT exchange yields: the server's
// identification string, its offer, and the algorithms RFC 4253 §7.1 selects
// from that offer against sshProbeOffer.
type sshKexInitCapture struct {
	Banner          string // full identification string, bounded and redacted
	ProtocolVersion string // catalogue code, e.g. "SSH-2.0"
	SoftwareVersion string // the softwareversion field, e.g. "OpenSSH_9.6p1"

	// Offered — the server's KEXINIT name-lists, verbatim and in server order.
	ServerKex            []string
	ServerHostKey        []string
	ServerEncryptionC2S  []string
	ServerEncryptionS2C  []string
	ServerMACC2S         []string
	ServerMACS2C         []string
	ServerCompressionC2S []string
	ServerCompressionS2C []string

	// Negotiated — derived, not observed. See negotiate().
	Kex            string
	HostKey        string
	EncryptionC2S  string
	EncryptionS2C  string
	MACC2S         string
	MACS2C         string
	CompressionC2S string
}

// negotiate fills the negotiated fields from the server's offer against
// sshProbeOffer, per RFC 4253 §7.1, by delegating to
// cryptoparse.NegotiateSSHAlgorithm — the same function the inventory ingest
// uses to reconstruct a negotiated algorithm from a passive capture's two
// name-lists. One definition of "what SSH would choose", used by both
// runtimes and by ingest, so the probe and the ingest can never disagree.
//
// The MAC is negotiated and recorded even when the cipher is AEAD. Suppressing
// it is the INGEST's call (cryptoparse.IsSSHAEADCipher, applied in
// ssh_ingest.go) because that is where "what this configuration uses" is
// written to a column; here the field records what the name-lists resolve to,
// which is the same answer any SSH implementation would compute.
func (c *sshKexInitCapture) negotiate() {
	c.Kex = cryptoparse.NegotiateSSHAlgorithm(sshProbeOffer.Kex, c.ServerKex)
	c.HostKey = cryptoparse.NegotiateSSHAlgorithm(sshProbeOffer.HostKey, c.ServerHostKey)
	c.EncryptionC2S = cryptoparse.NegotiateSSHAlgorithm(sshProbeOffer.Encryption, c.ServerEncryptionC2S)
	c.EncryptionS2C = cryptoparse.NegotiateSSHAlgorithm(sshProbeOffer.Encryption, c.ServerEncryptionS2C)
	c.MACC2S = cryptoparse.NegotiateSSHAlgorithm(sshProbeOffer.MAC, c.ServerMACC2S)
	c.MACS2C = cryptoparse.NegotiateSSHAlgorithm(sshProbeOffer.MAC, c.ServerMACS2C)
	c.CompressionC2S = cryptoparse.NegotiateSSHAlgorithm(sshProbeOffer.Compression, c.ServerCompressionC2S)
}

// sshprobeKexInit dials address, performs the SSH version exchange and the
// KEXINIT exchange, and returns what the server offered plus what would be
// negotiated.
//
// # Why this costs a second TCP connection, and why it cannot not
//
// An SSH probe now opens TWO connections to each host: this one, and the one
// probe_ssh.go hands to the x/crypto handshake for the host key fingerprint.
// The two cannot be folded into one. Both the version exchange and KEXINIT
// happen exactly once per connection, and ssh.NewClientConn performs its own —
// it takes a raw net.Conn and drives the handshake from the first byte, with
// no way to hand it a connection whose version exchange is already done and
// whose KEXINIT is already committed. Reusing this connection for the
// handshake would mean reimplementing the key exchange itself, which is where
// key material would start existing inside the probe.
//
// So the cost is one extra short-lived connection per SSH host. This one
// closes as soon as the server's KEXINIT has been read — before any key
// exchange — so it is cheaper and shorter-lived than the handshake pass it
// accompanies. The alternative was keeping every SSH server in the inventory
// unassessed.
func sshprobeKexInit(p *Prober, address string) (*sshKexInitCapture, error) {
	conn, err := net.DialTimeout("tcp", address, p.timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect for SSH KEXINIT: %w", err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(p.timeout)); err != nil {
		return nil, fmt.Errorf("failed to set SSH KEXINIT deadline: %w", err)
	}
	return sshKexInitExchange(conn)
}

// sshKexInitExchange runs the version + KEXINIT exchange over an already
// connected, already deadlined conn. Split out from sshprobeKexInit so a test
// can drive it over a net.Pipe or an in-process listener without dialing.
func sshKexInitExchange(conn net.Conn) (*sshKexInitCapture, error) {
	r := bufio.NewReader(conn)

	// RFC 4253 §4.2 lets both sides send their identification string without
	// waiting for the other, so ours goes first and the read below overlaps
	// the server's own write.
	if _, err := conn.Write([]byte(sshClientIdentification + "\r\n")); err != nil {
		return nil, fmt.Errorf("failed to send SSH identification: %w", err)
	}

	banner, err := sshReadIdentification(r)
	if err != nil {
		return nil, err
	}

	capture := &sshKexInitCapture{
		Banner:          boundSSHBanner(banner),
		ProtocolVersion: cryptoparse.SSHProtocolVersionCode(banner),
		SoftwareVersion: sshSoftwareVersion(banner),
	}

	if _, err := conn.Write(sshWrapPacket(sshBuildKexInitPayload())); err != nil {
		return nil, fmt.Errorf("failed to send SSH KEXINIT: %w", err)
	}

	payload, err := sshReadUntilKexInit(r)
	if err != nil {
		return nil, err
	}
	if err := capture.parse(payload); err != nil {
		return nil, err
	}
	capture.negotiate()
	return capture, nil
}

// errSSHPreambleBound is returned when a peer sends more bytes before its
// identification string than sshMaxPreambleBytes allows.
var errSSHPreambleBound = errors.New("SSH identification not seen within preamble bound")

// sshReadIdentification reads the server's identification string, skipping
// any preamble lines that precede it (RFC 4253 §4.2). Preamble lines are
// discarded rather than stored: they are operator-authored legal banners that
// can hold anything, and the probe has no use for their contents.
//
// The peer here is unauthenticated and arbitrary, so the byte bound has to
// hold DURING the read, not after it. This used to call
// bufio.Reader.ReadString, which grows a buffer until it finds the delimiter:
// against a peer streaming bytes with no newline at all, the bound was only
// consulted once ReadString returned, which it would not do until the
// connection deadline — gigabytes later. With the in-cluster prober's timeout
// and its scan concurrency that is an OOM of the pod, or of a customer's
// sensor host.
//
// sshReadBoundedLine uses ReadSlice, which reads into bufio's fixed buffer and
// reports bufio.ErrBufferFull rather than growing, so memory stays bounded
// however much the peer sends and the byte cap ends the read.
func sshReadIdentification(r *bufio.Reader) (string, error) {
	consumed := 0
	for i := 0; i < sshMaxPreambleLines; i++ {
		line, overlong, err := sshReadBoundedLine(r, &consumed)
		if err != nil {
			// A server that closed after writing an identification string
			// without a newline still told us what it is.
			if errors.Is(err, io.EOF) && !overlong && strings.HasPrefix(line, "SSH-") {
				return strings.TrimRight(line, "\r\n"), nil
			}
			return "", fmt.Errorf("failed to read SSH identification: %w", err)
		}
		if overlong {
			// RFC 4253 §4.2 caps the identification string at 255 bytes, so a
			// longer line cannot be one. It is preamble; skip it.
			continue
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, "SSH-") {
			return line, nil
		}
	}
	return "", errors.New("SSH identification not seen within preamble line bound")
}

// maxSSHIdentificationLen is RFC 4253 §4.2's cap on the identification string,
// 255 bytes including the CR LF. It bounds how much of any one line is
// retained: a longer line is definitionally not an identification string, and
// preamble lines are discarded anyway, so there is never a reason to hold more.
const maxSSHIdentificationLen = 255

// sshReadBoundedLine reads one newline-terminated line, retaining at most
// maxSSHIdentificationLen bytes of it and charging every byte it consumes
// against *consumed.
//
// It reports overlong=true when the line on the wire was longer than an
// identification string may be, so the caller can skip it without having held
// it. The returned error is errSSHPreambleBound once the peer has spent the
// whole preamble budget, io.EOF at a clean end of stream, or the transport's
// own error.
func sshReadBoundedLine(r *bufio.Reader, consumed *int) (line string, overlong bool, err error) {
	var buf []byte
	total := 0

	for {
		// ReadSlice returns a slice of bufio's OWN buffer and never allocates
		// a larger one; on a line longer than that buffer it returns what it
		// has with bufio.ErrBufferFull. That is what keeps this bounded.
		chunk, rerr := r.ReadSlice('\n')
		total += len(chunk)
		*consumed += len(chunk)

		if room := maxSSHIdentificationLen - len(buf); room > 0 {
			take := chunk
			if len(take) > room {
				take = take[:room]
			}
			buf = append(buf, take...)
		}

		if *consumed > sshMaxPreambleBytes {
			return string(buf), true, errSSHPreambleBound
		}
		if rerr == nil {
			return string(buf), total > maxSSHIdentificationLen, nil
		}
		if errors.Is(rerr, bufio.ErrBufferFull) {
			// Keep draining this over-long line. Nothing past the cap above
			// is retained, and the byte budget still ends it.
			continue
		}
		return string(buf), total > maxSSHIdentificationLen, rerr
	}
}

// sshSoftwareVersion extracts the softwareversion field of an identification
// string: "SSH-protoversion-softwareversion SP comments". The optional
// comments field is dropped — it is free text and not part of the software
// identity.
func sshSoftwareVersion(banner string) string {
	b := strings.TrimSpace(banner)
	if len(b) < 4 || !strings.EqualFold(b[:4], "SSH-") {
		return ""
	}
	rest := b[4:]
	i := strings.Index(rest, "-")
	if i < 0 {
		return ""
	}
	software := rest[i+1:]
	if sp := strings.IndexAny(software, " \t"); sp >= 0 {
		software = software[:sp]
	}
	return strings.TrimSpace(software)
}

// sshReadUntilKexInit reads transport packets until the server's KEXINIT
// arrives. A server may precede it with SSH_MSG_IGNORE or SSH_MSG_DEBUG, so
// other message types are skipped rather than treated as an error — but only
// up to sshMaxTransportPackets, so a peer that never sends KEXINIT cannot
// keep the probe reading until its deadline.
func sshReadUntilKexInit(r io.Reader) ([]byte, error) {
	for i := 0; i < sshMaxTransportPackets; i++ {
		payload, err := sshReadPacket(r)
		if err != nil {
			return nil, err
		}
		if len(payload) > 0 && payload[0] == sshMsgKexInit {
			return payload, nil
		}
	}
	return nil, errors.New("no SSH_MSG_KEXINIT within packet bound")
}

// sshReadPacket reads one cleartext binary-protocol packet (RFC 4253 §6) and
// returns its payload. Only valid before NEWKEYS, which is the only place
// this probe ever reads.
func sshReadPacket(r io.Reader) ([]byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, fmt.Errorf("failed to read SSH packet header: %w", err)
	}

	packetLen := binary.BigEndian.Uint32(header[0:4])
	paddingLen := uint32(header[4])

	// packet_length covers the padding_length byte, the payload and the
	// padding. A payload must hold at least the message number.
	if packetLen > sshMaxPacketLen {
		return nil, fmt.Errorf("SSH packet length %d exceeds bound %d", packetLen, sshMaxPacketLen)
	}
	// RFC 4253 §6 sets a minimum of 4 padding bytes, which sshWrapPacket
	// honours on the way out; the parser holds the peer to the same rule
	// rather than accepting a frame this implementation would never produce.
	if paddingLen < sshMinPadding {
		return nil, fmt.Errorf("malformed SSH packet: padding %d, RFC 4253 §6 requires at least %d", paddingLen, sshMinPadding)
	}
	if packetLen < paddingLen+2 {
		return nil, fmt.Errorf("malformed SSH packet: length %d, padding %d", packetLen, paddingLen)
	}

	body := make([]byte, packetLen-1)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("failed to read SSH packet body: %w", err)
	}
	return body[:uint32(len(body))-paddingLen], nil
}

// sshWrapPacket frames a payload as a cleartext binary-protocol packet
// (RFC 4253 §6): the total of packet_length, padding_length, payload and
// padding must be a multiple of 8 before any cipher is in effect, with at
// least 4 bytes of padding.
func sshWrapPacket(payload []byte) []byte {
	const blockSize = 8
	paddingLen := blockSize - ((4 + 1 + len(payload)) % blockSize)
	if paddingLen < sshMinPadding {
		paddingLen += blockSize
	}

	packetLen := 1 + len(payload) + paddingLen
	out := make([]byte, 0, 4+packetLen)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(packetLen))
	out = append(out, lenBuf[:]...)
	out = append(out, byte(paddingLen))
	out = append(out, payload...)

	padding := make([]byte, paddingLen)
	// crypto/rand.Read never returns an error in Go 1.24+; padding is not
	// security-critical here (nothing is keyed off it) but random padding is
	// what the protocol specifies.
	_, _ = rand.Read(padding)
	return append(out, padding...)
}

// sshBuildKexInitPayload builds an SSH_MSG_KEXINIT payload advertising
// sshProbeOffer (RFC 4253 §7.1).
func sshBuildKexInitPayload() []byte {
	var buf bytes.Buffer
	buf.WriteByte(sshMsgKexInit)

	cookie := make([]byte, 16)
	_, _ = rand.Read(cookie)
	buf.Write(cookie)

	lists := [sshNameListFields][]string{
		sshProbeOffer.Kex,
		sshProbeOffer.HostKey,
		sshProbeOffer.Encryption, // client to server
		sshProbeOffer.Encryption, // server to client
		sshProbeOffer.MAC,        // client to server
		sshProbeOffer.MAC,        // server to client
		sshProbeOffer.Compression,
		sshProbeOffer.Compression,
		nil, // languages, client to server
		nil, // languages, server to client
	}
	for _, l := range lists {
		sshWriteString(&buf, strings.Join(l, ","))
	}

	buf.WriteByte(0)              // first_kex_packet_follows: no guess sent
	buf.Write([]byte{0, 0, 0, 0}) // reserved, always zero
	return buf.Bytes()
}

// sshWriteString writes an RFC 4251 §5 string: a uint32 length followed by
// that many bytes.
func sshWriteString(buf *bytes.Buffer, s string) {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(s)))
	buf.Write(lenBuf[:])
	buf.WriteString(s)
}

// sshReadString reads an RFC 4251 §5 string, returning it and the remaining
// bytes.
func sshReadString(b []byte) (string, []byte, bool) {
	if len(b) < 4 {
		return "", nil, false
	}
	n := binary.BigEndian.Uint32(b[0:4])
	if uint64(n) > uint64(len(b)-4) {
		return "", nil, false
	}
	return string(b[4 : 4+n]), b[4+n:], true
}

// parse fills the offered name-lists from a KEXINIT payload (RFC 4253 §7.1):
// the message number, a 16-byte cookie, ten name-lists, a boolean and a
// reserved uint32.
func (c *sshKexInitCapture) parse(payload []byte) error {
	const headerLen = 1 + 16
	if len(payload) < headerLen || payload[0] != sshMsgKexInit {
		return errors.New("not an SSH_MSG_KEXINIT payload")
	}

	rest := payload[headerLen:]
	var lists [sshNameListFields][]string
	for i := 0; i < sshNameListFields; i++ {
		s, remainder, ok := sshReadString(rest)
		if !ok {
			return fmt.Errorf("truncated SSH_MSG_KEXINIT at name-list %d", i+1)
		}
		lists[i] = sshSplitNameList(s)
		rest = remainder
	}

	c.ServerKex = lists[0]
	c.ServerHostKey = lists[1]
	c.ServerEncryptionC2S = lists[2]
	c.ServerEncryptionS2C = lists[3]
	c.ServerMACC2S = lists[4]
	c.ServerMACS2C = lists[5]
	c.ServerCompressionC2S = lists[6]
	c.ServerCompressionS2C = lists[7]
	// lists[8] and lists[9] are the language name-lists, which carry no
	// cryptographic posture and are in practice always empty.
	return nil
}

// sshSplitNameList splits an RFC 4251 §5 name-list (comma separated, no
// spaces) and drops empty entries. An empty list is returned as nil so a
// caller can tell "the server offered nothing" from "the server offered an
// entry we could not read".
func sshSplitNameList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
