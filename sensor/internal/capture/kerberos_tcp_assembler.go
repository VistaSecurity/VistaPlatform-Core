package capture

import (
	"encoding/binary"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/tcpassembly"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
)

const (
	krbTCPMaxMessage = 1024 * 1024 // RFC-safe upper bound for a single KRB5 TCP record
	krbTCPMaxBuffer  = krbTCPMaxMessage + 4096
)

// kerberosTCPState buffers one direction of a Kerberos-over-TCP stream (4-byte length + ASN.1).
type kerberosTCPState struct {
	sessionID  string
	serverIP   string
	serverPort int
	clientIP   string
	clientPort int
	iface      string
	buffer     []byte
	lastSeen   time.Time
}

// KerberosTCPStreamFactory creates KerberosTCPStream instances for TCP port 88.
type KerberosTCPStreamFactory struct {
	mu           sync.Mutex
	sessions     map[tlsFlowKey]*kerberosTCPState
	ifacePending sync.Map // tlsFlowKey -> string (capture interface); cleared in New
	discoveries  chan<- *models.CryptoDiscovery
	sensorID     string
}

// NewKerberosTCPStreamFactory builds a factory for length-framed Kerberos TCP parsing.
func NewKerberosTCPStreamFactory(discoveries chan<- *models.CryptoDiscovery, sensorID string) *KerberosTCPStreamFactory {
	return &KerberosTCPStreamFactory{
		sessions:    make(map[tlsFlowKey]*kerberosTCPState),
		discoveries: discoveries,
		sensorID:    sensorID,
	}
}

// RegisterIfaceForFlow records the capture interface for the next Assembler lookup for this flow key.
func (f *KerberosTCPStreamFactory) RegisterIfaceForFlow(key tlsFlowKey, iface string) {
	if iface != "" {
		f.ifacePending.Store(key, iface)
	}
}

// KerberosTCPStream reassembles Kerberos messages on a single TCP stream direction.
type KerberosTCPStream struct {
	factory *KerberosTCPStreamFactory
	key     tlsFlowKey
	state   *kerberosTCPState
}

func (f *KerberosTCPStreamFactory) New(netFlow, transportFlow gopacket.Flow) tcpassembly.Stream {
	key := tlsFlowKey{net: netFlow, transport: transportFlow}
	dstPort := int(binary.BigEndian.Uint16(transportFlow.Dst().Raw()))
	srcPort := int(binary.BigEndian.Uint16(transportFlow.Src().Raw()))

	serverIP := netFlow.Dst().String()
	serverPort := dstPort
	clientIP := netFlow.Src().String()
	clientPort := srcPort
	if srcPort == 88 {
		serverIP = netFlow.Src().String()
		serverPort = srcPort
		clientIP = netFlow.Dst().String()
		clientPort = dstPort
	}

	iface := ""
	if v, ok := f.ifacePending.LoadAndDelete(key); ok {
		iface, _ = v.(string)
	}

	f.mu.Lock()
	state, exists := f.sessions[key]
	if !exists {
		state = &kerberosTCPState{
			sessionID:  uuid.New().String(),
			serverIP:   serverIP,
			serverPort: serverPort,
			clientIP:   clientIP,
			clientPort: clientPort,
			iface:      iface,
			lastSeen:   time.Now(),
		}
		f.sessions[key] = state
	} else {
		if iface != "" && state.iface == "" {
			state.iface = iface
		}
		state.lastSeen = time.Now()
	}
	f.mu.Unlock()

	return &KerberosTCPStream{factory: f, key: key, state: state}
}

func (s *KerberosTCPStream) Reassembled(reassembly []tcpassembly.Reassembly) {
	for _, r := range reassembly {
		if r.Skip != 0 {
			s.state.buffer = nil
		}
		if len(r.Bytes) > 0 {
			s.state.buffer = append(s.state.buffer, r.Bytes...)
		}
		s.state.lastSeen = time.Now()
	}
	if len(s.state.buffer) > krbTCPMaxBuffer {
		s.state.buffer = s.state.buffer[len(s.state.buffer)-krbTCPMaxBuffer:]
	}
	s.processBuffer()
}

func (s *KerberosTCPStream) ReassemblyComplete() {
	s.processBuffer()
	s.factory.mu.Lock()
	delete(s.factory.sessions, s.key)
	s.factory.mu.Unlock()
}

func (s *KerberosTCPStream) processBuffer() {
	for len(s.state.buffer) >= 4 {
		msgLen := int(binary.BigEndian.Uint32(s.state.buffer[:4]))
		if msgLen < 10 || msgLen > krbTCPMaxMessage {
			// Lose sync: shift one byte and try to recover (same idea as TLS buffer recovery).
			s.state.buffer = s.state.buffer[1:]
			continue
		}
		if len(s.state.buffer) < 4+msgLen {
			return
		}
		msg := s.state.buffer[4 : 4+msgLen]
		s.state.buffer = s.state.buffer[4+msgLen:]

		discovery := parseKerberosPacket(msg, s.state.clientIP, s.state.serverIP, s.state.clientPort, s.state.serverPort, s.factory.sensorID, s.state.iface)
		if discovery != nil {
			select {
			case s.factory.discoveries <- discovery:
			default:
				log.Printf("Warning: Kerberos TCP discovery channel full, dropping session %s", s.state.sessionID)
			}
		}
	}
}
