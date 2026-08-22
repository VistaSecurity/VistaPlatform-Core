package capture

import (
	"context"
	"crypto/ecdsa"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"math"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/gopacket/gopacket/tcpassembly"
	"github.com/vistasecurity/vistaplatform/sensor/internal/cache"
	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
	"github.com/vistasecurity/vistaplatform/sensor/internal/crypto"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
)

// capturedPacket pairs a raw packet with the interface it arrived on
type capturedPacket struct {
	pkt   gopacket.Packet
	iface string
}

// PacketCapture handles network packet capture
type PacketCapture struct {
	config             *config.Config
	interfaces         []string
	handles            []*pcap.Handle
	ctx                context.Context
	cancel             context.CancelFunc
	wg                 sync.WaitGroup
	discoveries        chan *models.CryptoDiscovery
	errors             chan error
	cache              *cache.ConnectionCache // Connection deduplication cache
	workers            chan capturedPacket    // bounded worker pool input
	assembler          *tcpassembly.Assembler
	streamFactory      *TLSStreamFactory
	sshStreamFactory   *SSHStreamFactory
	sshAssembler       *tcpassembly.Assembler
	starttlsFactory    *STARTTLSStreamFactory
	starttlsAssembler  *tcpassembly.Assembler
	smbFactory         *SMBStreamFactory
	smbAssembler       *tcpassembly.Assembler
	kerberosTCPFactory *KerberosTCPStreamFactory
	krbTCPAssembler    *tcpassembly.Assembler
	modbusFactory      *ModbusStreamFactory
	modbusAssembler    *tcpassembly.Assembler
	mmsFactory         *MMSStreamFactory
	mmsAssembler       *tcpassembly.Assembler
	dnp3Factory        *DNP3StreamFactory
	dnp3Assembler      *tcpassembly.Assembler
	opcuaFactory       *OPCUAStreamFactory
	opcuaAssembler     *tcpassembly.Assembler
	enipFactory        *ENIPStreamFactory
	enipAssembler      *tcpassembly.Assembler
	hartipFactory      *HARTIPStreamFactory
	hartipAssembler    *tcpassembly.Assembler
	starttlsPorts      []int      // resolved list (defaults applied) for routing + factory parity
	assemblerMu        sync.Mutex // protects assemblers (not concurrent-safe)
	packetCount        int64      // atomic counter
	dropCount          int64      // atomic counter
}

// NewPacketCapture creates a new packet capture instance
func NewPacketCapture(cfg *config.Config) *PacketCapture {
	ctx, cancel := context.WithCancel(context.Background())
	workerCount := runtime.NumCPU()

	dedupTTL := time.Duration(cfg.Capture.DedupTTLMinutes) * time.Minute

	discoveries := make(chan *models.CryptoDiscovery, 1000)
	connCache := cache.NewConnectionCache(dedupTTL, 100000)

	// STARTTLS ports (defaults when unset) — used for BPF, routing, STARTTLS factory, and TLS factory
	starttlsPorts := cfg.Capture.STARTTLSPorts
	if len(starttlsPorts) == 0 {
		starttlsPorts = []int{25, 143, 110, 5432, 3306, 21, 5222, 389}
	}

	streamFactory := NewTLSStreamFactory(discoveries, cfg.SensorID, connCache, cfg.Capture.EnableSTARTTLS, starttlsPorts)
	pool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(pool)
	assembler.MaxBufferedPagesPerConnection = 16
	assembler.MaxBufferedPagesTotal = 1000

	sshStreamFactory := NewSSHStreamFactory(discoveries, cfg.SensorID, connCache)
	sshPool := tcpassembly.NewStreamPool(sshStreamFactory)
	sshAssembler := tcpassembly.NewAssembler(sshPool)
	sshAssembler.MaxBufferedPagesPerConnection = 8
	sshAssembler.MaxBufferedPagesTotal = 500
	var starttlsFactory *STARTTLSStreamFactory
	var starttlsAssembler *tcpassembly.Assembler
	if cfg.Capture.EnableSTARTTLS {
		starttlsFactory = NewSTARTTLSStreamFactory(discoveries, cfg.SensorID, connCache, starttlsPorts)
		starttlsPool := tcpassembly.NewStreamPool(starttlsFactory)
		starttlsAssembler = tcpassembly.NewAssembler(starttlsPool)
		starttlsAssembler.MaxBufferedPagesPerConnection = 8
		starttlsAssembler.MaxBufferedPagesTotal = 500
	}
	var smbFactory *SMBStreamFactory
	var smbAssemblerInst *tcpassembly.Assembler
	if cfg.Capture.EnableSMB {
		smbFactory = NewSMBStreamFactory(discoveries, cfg.SensorID, connCache)
		smbPool := tcpassembly.NewStreamPool(smbFactory)
		smbAssemblerInst = tcpassembly.NewAssembler(smbPool)
		smbAssemblerInst.MaxBufferedPagesPerConnection = 8
		smbAssemblerInst.MaxBufferedPagesTotal = 500
	}
	var krbTCPFactory *KerberosTCPStreamFactory
	var krbTCPAssembler *tcpassembly.Assembler
	if cfg.Capture.EnableKerberos {
		krbTCPFactory = NewKerberosTCPStreamFactory(discoveries, cfg.SensorID)
		krbPool := tcpassembly.NewStreamPool(krbTCPFactory)
		krbTCPAssembler = tcpassembly.NewAssembler(krbPool)
		krbTCPAssembler.MaxBufferedPagesPerConnection = 8
		krbTCPAssembler.MaxBufferedPagesTotal = 500
	}
	var modbusFactory *ModbusStreamFactory
	var modbusAssembler *tcpassembly.Assembler
	if cfg.Capture.EnableModbus {
		modbusFactory = NewModbusStreamFactory(discoveries, cfg.SensorID, connCache)
		modbusPool := tcpassembly.NewStreamPool(modbusFactory)
		modbusAssembler = tcpassembly.NewAssembler(modbusPool)
		modbusAssembler.MaxBufferedPagesPerConnection = 4
		modbusAssembler.MaxBufferedPagesTotal = 200
	}
	var mmsFactory *MMSStreamFactory
	var mmsAssembler *tcpassembly.Assembler
	if cfg.Capture.EnableMMS {
		mmsFactory = NewMMSStreamFactory(discoveries, cfg.SensorID, connCache)
		mmsPool := tcpassembly.NewStreamPool(mmsFactory)
		mmsAssembler = tcpassembly.NewAssembler(mmsPool)
		mmsAssembler.MaxBufferedPagesPerConnection = 8
		mmsAssembler.MaxBufferedPagesTotal = 500
	}
	var dnp3Factory *DNP3StreamFactory
	var dnp3Assembler *tcpassembly.Assembler
	if cfg.Capture.EnableDNP3 {
		dnp3Factory = NewDNP3StreamFactory(discoveries, cfg.SensorID, connCache)
		dnp3Pool := tcpassembly.NewStreamPool(dnp3Factory)
		dnp3Assembler = tcpassembly.NewAssembler(dnp3Pool)
		dnp3Assembler.MaxBufferedPagesPerConnection = 8
		dnp3Assembler.MaxBufferedPagesTotal = 500
	}
	var opcuaFactory *OPCUAStreamFactory
	var opcuaAssembler *tcpassembly.Assembler
	if cfg.Capture.EnableOPCUA {
		opcuaFactory = NewOPCUAStreamFactory(discoveries, cfg.SensorID, connCache)
		opcuaPool := tcpassembly.NewStreamPool(opcuaFactory)
		opcuaAssembler = tcpassembly.NewAssembler(opcuaPool)
		opcuaAssembler.MaxBufferedPagesPerConnection = 8
		opcuaAssembler.MaxBufferedPagesTotal = 500
	}
	var enipFactory *ENIPStreamFactory
	var enipAssembler *tcpassembly.Assembler
	if cfg.Capture.EnableENIP {
		enipFactory = NewENIPStreamFactory(discoveries, cfg.SensorID, connCache)
		enipPool := tcpassembly.NewStreamPool(enipFactory)
		enipAssembler = tcpassembly.NewAssembler(enipPool)
		enipAssembler.MaxBufferedPagesPerConnection = 8
		enipAssembler.MaxBufferedPagesTotal = 500
	}
	var hartipFactory *HARTIPStreamFactory
	var hartipAssembler *tcpassembly.Assembler
	if cfg.Capture.EnableHARTIP {
		hartipFactory = NewHARTIPStreamFactory(discoveries, cfg.SensorID, connCache)
		hartipPool := tcpassembly.NewStreamPool(hartipFactory)
		hartipAssembler = tcpassembly.NewAssembler(hartipPool)
		hartipAssembler.MaxBufferedPagesPerConnection = 8
		hartipAssembler.MaxBufferedPagesTotal = 500
	}

	return &PacketCapture{
		config:             cfg,
		interfaces:         cfg.Capture.Interfaces,
		ctx:                ctx,
		cancel:             cancel,
		discoveries:        discoveries,
		errors:             make(chan error, 100),
		cache:              connCache,
		workers:            make(chan capturedPacket, workerCount*64),
		assembler:          assembler,
		streamFactory:      streamFactory,
		sshStreamFactory:   sshStreamFactory,
		sshAssembler:       sshAssembler,
		starttlsFactory:    starttlsFactory,
		starttlsAssembler:  starttlsAssembler,
		smbFactory:         smbFactory,
		smbAssembler:       smbAssemblerInst,
		kerberosTCPFactory: krbTCPFactory,
		krbTCPAssembler:    krbTCPAssembler,
		modbusFactory:      modbusFactory,
		modbusAssembler:    modbusAssembler,
		mmsFactory:         mmsFactory,
		mmsAssembler:       mmsAssembler,
		dnp3Factory:        dnp3Factory,
		dnp3Assembler:      dnp3Assembler,
		opcuaFactory:       opcuaFactory,
		opcuaAssembler:     opcuaAssembler,
		enipFactory:        enipFactory,
		enipAssembler:      enipAssembler,
		hartipFactory:      hartipFactory,
		hartipAssembler:    hartipAssembler,
		starttlsPorts:      starttlsPorts,
	}
}

// SetCache sets a custom connection cache (for testing or custom TTL)
func (pc *PacketCapture) SetCache(c *cache.ConnectionCache) {
	pc.cache = c
}

// GetCache returns the connection cache
func (pc *PacketCapture) GetCache() *cache.ConnectionCache {
	return pc.cache
}

// Start begins packet capture on all configured interfaces
func (pc *PacketCapture) Start() error {
	log.Printf("Starting packet capture on interfaces: %v", pc.interfaces)

	for _, iface := range pc.interfaces {
		if err := pc.startInterfaceCapture(iface); err != nil {
			log.Printf("Failed to start capture on interface %s: %v", iface, err)
			continue
		}
	}

	if len(pc.handles) == 0 {
		return fmt.Errorf("no interfaces available for capture\n\n" +
			"🚨 NO NETWORK INTERFACES AVAILABLE\n" +
			"==================================\n" +
			"This usually means:\n\n" +
			"1. Packet capture library not installed (Windows):\n" +
			"   - Install Npcap: https://npcap.com/\n" +
			"   - Or WinPcap: https://www.winpcap.org/\n" +
			"   - Restart computer after installation\n\n" +
			"2. Not running as Administrator (Windows):\n" +
			"   - Right-click Command Prompt → 'Run as administrator'\n\n" +
			"3. No network interfaces configured:\n" +
			"   - Check network adapter settings\n" +
			"   - Ensure network interfaces are active\n\n" +
			"4. Permission issues (Linux/macOS):\n" +
			"   - Run with sudo: sudo ./crypto-sensor\n\n" +
			"See WINDOWS_SETUP.md for detailed Windows setup instructions")
	}

	// Start bounded worker goroutines — these consume from the workers channel
	// and are NOT tracked by wg (they exit via ctx.Done, not interface close)
	workerCount := runtime.NumCPU()
	for i := 0; i < workerCount; i++ {
		go pc.runWorker()
	}

	// Periodically flush stale assembler streams
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-pc.ctx.Done():
				return
			case <-ticker.C:
				pc.streamFactory.FlushOldSessions(30 * time.Second)
				pc.sshStreamFactory.FlushOldSessions(30 * time.Second)
				if pc.starttlsFactory != nil {
					pc.starttlsFactory.FlushOldSessions(30 * time.Second)
				}
				if pc.modbusFactory != nil {
					pc.modbusFactory.FlushOldSessions(30 * time.Second)
				}
				if pc.mmsFactory != nil {
					pc.mmsFactory.FlushOldSessions(30 * time.Second)
				}
				if pc.dnp3Factory != nil {
					pc.dnp3Factory.FlushOldSessions(30 * time.Second)
				}
				if pc.opcuaFactory != nil {
					pc.opcuaFactory.FlushOldSessions(30 * time.Second)
				}
				if pc.enipFactory != nil {
					pc.enipFactory.FlushOldSessions(30 * time.Second)
				}
				if pc.hartipFactory != nil {
					pc.hartipFactory.FlushOldSessions(30 * time.Second)
				}
			}
		}
	}()

	log.Printf("Packet capture started on %d interfaces with %d workers", len(pc.handles), workerCount)
	return nil
}

// Stop stops packet capture
func (pc *PacketCapture) Stop() {
	log.Println("Stopping packet capture...")
	pc.assemblerMu.Lock()
	pc.assembler.FlushAll()
	pc.sshAssembler.FlushAll()
	if pc.starttlsAssembler != nil {
		pc.starttlsAssembler.FlushAll()
	}
	if pc.krbTCPAssembler != nil {
		pc.krbTCPAssembler.FlushAll()
	}
	if pc.modbusAssembler != nil {
		pc.modbusAssembler.FlushAll()
	}
	if pc.mmsAssembler != nil {
		pc.mmsAssembler.FlushAll()
	}
	if pc.dnp3Assembler != nil {
		pc.dnp3Assembler.FlushAll()
	}
	if pc.opcuaAssembler != nil {
		pc.opcuaAssembler.FlushAll()
	}
	if pc.enipAssembler != nil {
		pc.enipAssembler.FlushAll()
	}
	if pc.hartipAssembler != nil {
		pc.hartipAssembler.FlushAll()
	}
	pc.assemblerMu.Unlock()
	pc.cancel()

	// Close all handles — unblocks captureInterface goroutines blocked on Packets()
	for _, handle := range pc.handles {
		handle.Close()
	}

	// Wait for all captureInterface goroutines to exit before closing channels
	pc.wg.Wait()
	close(pc.workers)
	close(pc.discoveries)
	close(pc.errors)
	log.Println("Packet capture stopped")
}

// GetDiscoveries returns the discoveries channel (read-only).
func (pc *PacketCapture) GetDiscoveries() <-chan *models.CryptoDiscovery {
	return pc.discoveries
}

// GetDiscoveriesWritable returns the discoveries channel for writing.
// Used by the TLS enricher to inject enrichment discoveries into the same
// pipeline as passive discoveries.
func (pc *PacketCapture) GetDiscoveriesWritable() chan<- *models.CryptoDiscovery {
	return pc.discoveries
}

// GetErrors returns the errors channel
func (pc *PacketCapture) GetErrors() <-chan error {
	return pc.errors
}

// GetStats returns packet capture statistics
func (pc *PacketCapture) GetStats() (packetCount, dropCount int64) {
	return atomic.LoadInt64(&pc.packetCount), atomic.LoadInt64(&pc.dropCount)
}

// GetInterfaceStats returns packet statistics as a list of per-interface entries.
// Currently returns a single aggregate entry covering all interfaces.
func (pc *PacketCapture) GetInterfaceStats() []models.InterfaceStatEntry {
	pkt := atomic.LoadInt64(&pc.packetCount)
	drop := atomic.LoadInt64(&pc.dropCount)
	total := pkt + drop
	dropRate := 0.0
	if total > 0 {
		dropRate = float64(drop) / float64(total) * 100.0
	}
	return []models.InterfaceStatEntry{
		{
			InterfaceName: "aggregate",
			PacketCount:   pkt,
			DropCount:     drop,
			DropRatePct:   dropRate,
		},
	}
}

// defaultSnapLen mirrors the BufferSize default in internal/config (1 MB). It
// is the fallback whenever the configured value cannot be expressed as a
// positive int32 snaplen.
const defaultSnapLen int32 = 1024 * 1024

// snapLenFromConfig narrows the operator-configured capture buffer size to the
// int32 snaplen pcap.OpenLive takes.
//
// Capture.BufferSize is a plain int (config `bufferSize` / env `BUFFER_SIZE`),
// so on a 64-bit build a bare int32() conversion of a value above MaxInt32
// wraps to a NEGATIVE snaplen. libpcap then either rejects the handle or
// captures nothing, and the resulting error says nothing about the configured
// number that caused it — the sensor just silently stops seeing traffic.
//
// Values already representable pass through unchanged, so every configuration
// that works today keeps its exact behaviour; only the ones that cannot be
// represented fall back to the default instead of wrapping.
func snapLenFromConfig(bufferSize int) int32 {
	if bufferSize <= 0 || bufferSize > math.MaxInt32 {
		return defaultSnapLen
	}
	return int32(bufferSize)
}

// startInterfaceCapture starts packet capture on a specific interface
func (pc *PacketCapture) startInterfaceCapture(iface string) error {
	// Check if interface exists
	interfaces, err := pcap.FindAllDevs()
	if err != nil {
		// Provide helpful error message for common Windows issue
		if strings.Contains(err.Error(), "wpcap.dll") {
			return fmt.Errorf("failed to find network interfaces: %v\n\n"+
				"🚨 WINDOWS PACKET CAPTURE LIBRARY MISSING\n"+
				"==========================================\n"+
				"The sensor requires a packet capture library to monitor network traffic.\n"+
				"Please install one of the following:\n\n"+
				"1. Npcap (Recommended):\n"+
				"   - Download from: https://npcap.com/\n"+
				"   - Install with 'WinPcap API-compatible Mode' enabled\n"+
				"   - Restart your computer after installation\n\n"+
				"2. WinPcap (Legacy):\n"+
				"   - Download from: https://www.winpcap.org/\n"+
				"   - Install and restart your computer\n\n"+
				"3. Run as Administrator:\n"+
				"   - Right-click Command Prompt → 'Run as administrator'\n"+
				"   - Navigate to sensor directory and run again\n\n"+
				"See WINDOWS_SETUP.md for detailed instructions", err)
		}
		return fmt.Errorf("failed to find network interfaces: %v", err)
	}

	var found bool
	var deviceName string
	for _, dev := range interfaces {
		if dev.Name == iface {
			found = true
			deviceName = dev.Name
			break
		}
		// Also check description (for Windows friendly name matching)
		if strings.Contains(strings.ToLower(dev.Description), strings.ToLower(iface)) ||
			strings.Contains(strings.ToLower(iface), strings.ToLower(dev.Description)) {
			found = true
			deviceName = dev.Name
			break
		}
	}

	if !found {
		// Provide helpful error with available interfaces
		availableNames := make([]string, 0, len(interfaces))
		for _, dev := range interfaces {
			if dev.Description != "" {
				availableNames = append(availableNames, fmt.Sprintf("%s (%s)", dev.Name, dev.Description))
			} else {
				availableNames = append(availableNames, dev.Name)
			}
		}
		return fmt.Errorf("interface %s not found. Available interfaces: %v", iface, availableNames)
	}

	// Use the resolved device name
	iface = deviceName

	// Open interface for capture
	handle, err := pcap.OpenLive(iface, snapLenFromConfig(pc.config.Capture.BufferSize), true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open interface %s: %v", iface, err)
	}

	// Build BPF filter for crypto-related traffic.
	// Base set covers the most common TLS/SSH ports; operators can extend via config.
	basePorts := []string{"443", "22", "993", "995", "465", "587", "636", "5671", "8443", "853"}
	// UDP ports for QUIC, IKE/IPsec, and WireGuard
	udpParts := []string{"udp port 443", "udp port 500", "udp port 4500"}
	if pc.config.Capture.EnableWireGuard {
		udpParts = append(udpParts, "udp port 51820")
	}
	if pc.config.Capture.EnableOpenVPN {
		udpParts = append(udpParts, "udp port 1194")
	}
	if pc.config.Capture.EnableKerberos {
		udpParts = append(udpParts, "udp port 88")
	}
	// TCP 3389 for RDP (which uses TLS over TCP), TCP 445 for SMB, TCP 88 for Kerberos
	tcpExtra := []string{"tcp port 3389"}
	if pc.config.Capture.EnableSMB {
		tcpExtra = append(tcpExtra, "tcp port 445")
	}
	if pc.config.Capture.EnableKerberos {
		tcpExtra = append(tcpExtra, "tcp port 88")
	}
	// Modbus/TCP on 502 routes to the Modbus assembler; Modbus/TLS on 802
	// routes to the existing TLS assembler (handled automatically by the
	// "TLS" protocol classification once 802 is in getProtocolFromPort).
	if pc.config.Capture.EnableModbus {
		tcpExtra = append(tcpExtra, "tcp port 502", "tcp port 802")
	}
	// MMS / ICCP on 102 — routes to BOTH the MMS assembler (plaintext path)
	// and the TLS assembler (TLS-wrapped MMS / ICCP per IEC 62351-3). One
	// or the other fires depending on the wire bytes.
	if pc.config.Capture.EnableMMS {
		tcpExtra = append(tcpExtra, "tcp port 102")
	}
	// DNP3 on TCP port 20000 — passive only (no safe well-known active probe).
	// Also capture UDP 20000 for the (less common) UDP DNP3 path.
	if pc.config.Capture.EnableDNP3 {
		tcpExtra = append(tcpExtra, "tcp port 20000")
		udpParts = append(udpParts, "udp port 20000")
	}
	// OPC UA Binary on TCP 4840 — passive HEL/ACK detection plus OPN
	// SecurityPolicy URI extraction.
	if pc.config.Capture.EnableOPCUA {
		tcpExtra = append(tcpExtra, "tcp port 4840")
	}
	// EtherNet/IP CIP on TCP 44818 — passive encapsulation-header detection.
	// CIP Security (TLS-wrapped EtherNet/IP) goes through the TLS assembler.
	if pc.config.Capture.EnableENIP {
		tcpExtra = append(tcpExtra, "tcp port 44818")
	}
	// HART-IP (HCF Spec 85) on TCP+UDP 5094 — passive header-recognition.
	if pc.config.Capture.EnableHARTIP {
		tcpExtra = append(tcpExtra, "tcp port 5094")
		udpParts = append(udpParts, "udp port 5094")
	}
	filterParts := make([]string, 0, len(basePorts)+len(udpParts)+len(tcpExtra)+len(pc.config.Capture.ExtraPortsToMonitor)+len(pc.config.Capture.STARTTLSPorts))
	for _, p := range basePorts {
		filterParts = append(filterParts, "tcp port "+p)
	}
	filterParts = append(filterParts, udpParts...)
	filterParts = append(filterParts, tcpExtra...)
	for _, p := range pc.config.Capture.ExtraPortsToMonitor {
		filterParts = append(filterParts, fmt.Sprintf("tcp port %d", p))
	}
	// STARTTLS ports for plaintext protocols that may upgrade to TLS
	if pc.config.Capture.EnableSTARTTLS {
		for _, p := range pc.config.Capture.STARTTLSPorts {
			filterParts = append(filterParts, fmt.Sprintf("tcp port %d", p))
		}
	}
	filter := strings.Join(filterParts, " or ")
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Printf("Warning: Failed to set BPF filter on %s: %v", iface, err)
	}

	pc.handles = append(pc.handles, handle)

	// Start capture goroutine for this interface
	pc.wg.Add(1)
	go pc.captureInterface(handle, iface)

	return nil
}

// captureInterface captures packets from a specific interface and feeds the worker pool
func (pc *PacketCapture) captureInterface(handle *pcap.Handle, iface string) {
	defer pc.wg.Done()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for {
		select {
		case <-pc.ctx.Done():
			return
		case packet := <-packetSource.Packets():
			if packet == nil {
				continue
			}
			atomic.AddInt64(&pc.packetCount, 1)
			// Non-blocking send — drop if worker pool is saturated
			select {
			case pc.workers <- capturedPacket{pkt: packet, iface: iface}:
			default:
				atomic.AddInt64(&pc.dropCount, 1)
				log.Printf("Warning: Worker pool saturated, dropping packet on %s", iface)
			}
		}
	}
}

// runWorker is a fixed worker goroutine that processes packets from the bounded pool.
// Workers exit when the workers channel is closed (after all captureInterface goroutines finish).
func (pc *PacketCapture) runWorker() {
	for cp := range pc.workers {
		pc.analyzePacket(cp.pkt, cp.iface)
	}
}

// analyzePacket analyzes a captured packet for crypto information
func (pc *PacketCapture) analyzePacket(packet gopacket.Packet, iface string) {
	// Extract network layer information
	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return
	}

	// Extract transport layer information
	transportLayer := packet.TransportLayer()
	if transportLayer == nil {
		return
	}

	// Get source and destination information
	srcIP := networkLayer.NetworkFlow().Src().String()
	dstIP := networkLayer.NetworkFlow().Dst().String()
	srcPort := transportLayer.TransportFlow().Src().String()
	dstPort := transportLayer.TransportFlow().Dst().String()

	// Analyze based on port
	port := getPortNumber(dstPort)
	protocol := getProtocolFromPort(port, pc.config.Capture.EnableSTARTTLS, pc.starttlsPorts)

	if protocol == "" {
		return
	}

	// Handle UDP packets (QUIC, IKE/IPsec)
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		if udp, ok := udpLayer.(*layers.UDP); ok {
			udpSrcPort := int(udp.SrcPort)
			udpDstPort := int(udp.DstPort)
			udpProto := getUDPProtocolFromPort(udpDstPort)
			if udpProto == "" {
				udpProto = getUDPProtocolFromPort(udpSrcPort)
			}
			if udpProto != "" {
				appLayer := packet.ApplicationLayer()
				if appLayer != nil {
					payload := appLayer.Payload()
					var discovery *models.CryptoDiscovery
					switch udpProto {
					case "QUIC":
						discovery = parseQUICInitial(payload, srcIP, dstIP, getPortNumber(srcPort), getPortNumber(dstPort), pc.config.SensorID, iface, pc.config.Capture.EnableQUICDecrypt)
					case "IKE":
						// IKE may be on NAT-T (port 4500) with 4-byte non-ESP marker
						ikePkt := payload
						if udpDstPort == 4500 && len(payload) >= 4 {
							// Skip 4-byte Non-ESP Marker (0x00000000) if present
							marker := binary.BigEndian.Uint32(payload[:4])
							if marker == 0 {
								ikePkt = payload[4:]
							}
						}
						discovery = parseIKEHeader(ikePkt, srcIP, dstIP, getPortNumber(srcPort), getPortNumber(dstPort), pc.config.SensorID, iface)
					case "WireGuard":
						discovery = parseWireGuardPacket(payload, srcIP, dstIP, getPortNumber(srcPort), getPortNumber(dstPort), pc.config.SensorID, iface)
					case "OpenVPN":
						discovery = parseOpenVPNPacket(payload, srcIP, dstIP, getPortNumber(srcPort), getPortNumber(dstPort), pc.config.SensorID, iface)
					case "Kerberos":
						discovery = parseKerberosPacket(payload, srcIP, dstIP, getPortNumber(srcPort), getPortNumber(dstPort), pc.config.SensorID, iface)
					case "DNP3":
						if pc.config.Capture.EnableDNP3 {
							discovery = parseDNP3Packet(payload, srcIP, dstIP, getPortNumber(srcPort), getPortNumber(dstPort), pc.config.SensorID, iface, pc.cache)
						}
					case "HART_IP":
						if pc.config.Capture.EnableHARTIP {
							discovery = parseHARTIPPacket(payload, srcIP, dstIP, getPortNumber(srcPort), getPortNumber(dstPort), pc.config.SensorID, iface, pc.cache)
						}
					}
					if discovery != nil {
						select {
						case pc.discoveries <- discovery:
						default:
							log.Printf("Warning: Discovery channel full, dropping UDP discovery")
						}
					}
				}
			}
			return
		}
	}

	// For TCP packets with a known TLS/SSH protocol, feed to the appropriate stream
	// assembler which handles multi-packet reassembly and emits discoveries when sessions complete.
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		if tcp, ok := tcpLayer.(*layers.TCP); ok {
			flowKey := tlsFlowKey{net: networkLayer.NetworkFlow(), transport: tcp.TransportFlow()}
			if protocol == "SMB" && pc.smbFactory != nil {
				pc.smbFactory.RegisterIfaceForFlow(flowKey, iface)
			}
			if protocol == "Kerberos" && pc.kerberosTCPFactory != nil {
				pc.kerberosTCPFactory.RegisterIfaceForFlow(flowKey, iface)
			}
			if protocol == "Modbus" && pc.modbusFactory != nil {
				pc.modbusFactory.RegisterIfaceForFlow(flowKey, iface)
			}
			if protocol == "MMS" && pc.mmsFactory != nil {
				pc.mmsFactory.RegisterIfaceForFlow(flowKey, iface)
			}
			if protocol == "DNP3" && pc.dnp3Factory != nil {
				pc.dnp3Factory.RegisterIfaceForFlow(flowKey, iface)
			}
			if protocol == "OPC_UA" && pc.opcuaFactory != nil {
				pc.opcuaFactory.RegisterIfaceForFlow(flowKey, iface)
			}
			if protocol == "EtherNet_IP" && pc.enipFactory != nil {
				pc.enipFactory.RegisterIfaceForFlow(flowKey, iface)
			}
			if protocol == "HART_IP" && pc.hartipFactory != nil {
				pc.hartipFactory.RegisterIfaceForFlow(flowKey, iface)
			}
			pc.assemblerMu.Lock()
			if protocol == "SSH" {
				pc.sshAssembler.AssembleWithTimestamp(
					networkLayer.NetworkFlow(),
					tcp,
					packet.Metadata().Timestamp,
				)
			} else if protocol == "STARTTLS" && pc.starttlsAssembler != nil {
				pc.starttlsAssembler.AssembleWithTimestamp(
					networkLayer.NetworkFlow(),
					tcp,
					packet.Metadata().Timestamp,
				)
			} else if protocol == "Kerberos" && pc.krbTCPAssembler != nil {
				pc.krbTCPAssembler.AssembleWithTimestamp(
					networkLayer.NetworkFlow(),
					tcp,
					packet.Metadata().Timestamp,
				)
			} else if protocol == "SMB" && pc.smbAssembler != nil {
				pc.smbAssembler.AssembleWithTimestamp(
					networkLayer.NetworkFlow(),
					tcp,
					packet.Metadata().Timestamp,
				)
			} else if protocol == "Modbus" && pc.modbusAssembler != nil {
				pc.modbusAssembler.AssembleWithTimestamp(
					networkLayer.NetworkFlow(),
					tcp,
					packet.Metadata().Timestamp,
				)
			} else if protocol == "MMS" {
				// Port 102 dual-route: feed the MMS assembler (plaintext
				// path — TPKT/COTP framing) AND the TLS assembler
				// (TLS-wrapped MMS / ICCP per IEC 62351-3). One emits a
				// discovery; the other silently no-ops because the wire
				// bytes don't match its protocol.
				if pc.mmsAssembler != nil {
					pc.mmsAssembler.AssembleWithTimestamp(
						networkLayer.NetworkFlow(),
						tcp,
						packet.Metadata().Timestamp,
					)
				}
				pc.assembler.AssembleWithTimestamp(
					networkLayer.NetworkFlow(),
					tcp,
					packet.Metadata().Timestamp,
				)
			} else if protocol == "DNP3" && pc.dnp3Assembler != nil {
				pc.dnp3Assembler.AssembleWithTimestamp(
					networkLayer.NetworkFlow(),
					tcp,
					packet.Metadata().Timestamp,
				)
			} else if protocol == "OPC_UA" && pc.opcuaAssembler != nil {
				pc.opcuaAssembler.AssembleWithTimestamp(
					networkLayer.NetworkFlow(),
					tcp,
					packet.Metadata().Timestamp,
				)
			} else if protocol == "EtherNet_IP" && pc.enipAssembler != nil {
				pc.enipAssembler.AssembleWithTimestamp(
					networkLayer.NetworkFlow(),
					tcp,
					packet.Metadata().Timestamp,
				)
			} else if protocol == "HART_IP" && pc.hartipAssembler != nil {
				pc.hartipAssembler.AssembleWithTimestamp(
					networkLayer.NetworkFlow(),
					tcp,
					packet.Metadata().Timestamp,
				)
			} else {
				pc.assembler.AssembleWithTimestamp(
					networkLayer.NetworkFlow(),
					tcp,
					packet.Metadata().Timestamp,
				)
			}
			pc.assemblerMu.Unlock()
			return // Assembler handles discovery emission
		}
	}

	// Fallback: non-TCP path (should not normally be reached given BPF filter)
	// Check cache - skip if recently reported
	shouldReport, isNew := pc.cache.ShouldReport(dstIP, port, protocol)
	if !shouldReport {
		// Connection already reported recently, skip
		return
	}

	// Create discovery record
	discovery := &models.CryptoDiscovery{
		ID:              generateDiscoveryID(),
		SensorID:        pc.config.SensorID,
		Timestamp:       time.Now(),
		SourceIP:        srcIP,
		DestIP:          dstIP,
		Port:            port,
		Protocol:        protocol,
		DiscoveryMethod: "passive",
		Confidence:      0.8, // Default confidence for passive detection
		RawMetadata: map[string]interface{}{
			"interface":   iface,
			"src_port":    srcPort,
			"packet_size": len(packet.Data()),
			"is_new":      isNew, // Track if this is a new connection
		},
		CreatedAt: time.Now(),
	}

	// Analyze packet content for crypto details
	pc.analyzeCryptoDetails(packet, discovery)

	// Send discovery to channel
	select {
	case pc.discoveries <- discovery:
	default:
		// Channel is full, log warning
		log.Printf("Warning: Discovery channel full, dropping discovery")
	}
}

// analyzeCryptoDetails analyzes packet content for cryptographic details
func (pc *PacketCapture) analyzeCryptoDetails(packet gopacket.Packet, discovery *models.CryptoDiscovery) {
	// Get application layer
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer == nil {
		return
	}

	payload := applicationLayer.Payload()

	// Analyze based on protocol
	switch discovery.Protocol {
	case "TLS":
		pc.analyzeTLS(payload, discovery)
	case "SSH":
		pc.analyzeSSH(payload, discovery)
	}
}

// analyzeTLS analyzes a TLS record payload for handshake content.
// The record layer version (bytes 1-2) is unreliable for TLS 1.3 — it is always
// 0x0303 for backward compat.  Real version is determined from the
// supported_versions extension inside ClientHello/ServerHello.
func (pc *PacketCapture) analyzeTLS(payload []byte, discovery *models.CryptoDiscovery) {
	// TLS record header: ContentType(1) + LegacyVersion(2) + Length(2) = 5 bytes
	// Handshake record has ContentType 0x16.
	if len(payload) < 6 || payload[0] != 0x16 {
		return
	}

	handshakeType := payload[5]
	switch handshakeType {
	case 0x01: // ClientHello
		pc.analyzeClientHello(payload, discovery)
	case 0x02: // ServerHello
		pc.analyzeServerHello(payload, discovery)
	case 0x0B: // Certificate
		pc.analyzeCertificate(payload, discovery)
	}
}

// analyzeSSH analyzes SSH protocol data
func (pc *PacketCapture) analyzeSSH(payload []byte, discovery *models.CryptoDiscovery) {
	if len(payload) < 4 {
		return
	}

	// Check for SSH protocol identifier
	if string(payload[:4]) == "SSH-" {
		end := len(payload)
		for i, b := range payload {
			if b == '\n' || b == '\r' {
				end = i
				break
			}
		}
		banner := string(payload[:end])
		if end > 4 {
			discovery.Version = string(payload[4:end])
		}
		if discovery.RawMetadata == nil {
			discovery.RawMetadata = make(map[string]interface{})
		}
		discovery.RawMetadata["ssh_banner"] = banner
	}
}

// analyzeClientHello parses a TLS ClientHello handshake message.
//
// Wire format (RFC 5246 / 8446):
//
//	TLS record header : 5 bytes (ContentType, LegacyVersion[2], Length[2])
//	Handshake header  : 4 bytes (HandshakeType, Length[3])
//	client_version    : 2 bytes
//	random            : 32 bytes
//	session_id_length : 1 byte
//	session_id        : variable
//	cipher_suites_len : 2 bytes
//	cipher_suites     : variable (2 bytes each)
//	compress_methods  : 1+variable bytes
//	extensions_len    : 2 bytes
//	extensions        : variable
func (pc *PacketCapture) analyzeClientHello(payload []byte, discovery *models.CryptoDiscovery) {
	if discovery.RawMetadata == nil {
		discovery.RawMetadata = make(map[string]interface{})
	}
	discovery.RawMetadata["handshake_type"] = "ClientHello"
	discovery.Confidence = 0.9

	// Minimum required: record(5) + handshake(4) + version(2) + random(32) + sid_len(1) = 44
	if len(payload) < 44 {
		return
	}

	// Skip: record header(5) + handshake header(4) + client_version(2) + random(32) = offset 43
	offset := 43

	// session_id_length
	sidLen := int(payload[offset])
	offset++
	offset += sidLen // skip session_id

	if offset+2 > len(payload) {
		return
	}

	// cipher_suites_length (number of bytes, each suite is 2 bytes)
	csLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2

	if offset+csLen > len(payload) {
		return
	}

	var ciphers []string
	for i := 0; i+1 < csLen; i += 2 {
		suite := binary.BigEndian.Uint16(payload[offset+i : offset+i+2])
		if name := tlsCipherName(suite); name != "" {
			ciphers = append(ciphers, name)
		}
	}
	if len(ciphers) > 0 {
		discovery.RawMetadata["supported_ciphers"] = ciphers
	}
	offset += csLen

	// Skip compression methods
	if offset >= len(payload) {
		return
	}
	compLen := int(payload[offset])
	offset++
	offset += compLen

	// Parse extensions looking for supported_versions (0x002b)
	if offset+2 > len(payload) {
		return
	}
	extTotalLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2
	extEnd := offset + extTotalLen

	version := parseSupportedVersionsExt(payload, offset, extEnd)
	if version != "" {
		discovery.Version = version
	} else {
		// Fall back to the ClientHello client_version field (bytes 9-10)
		recVer := binary.BigEndian.Uint16(payload[9:11])
		discovery.Version = tlsVersionName(recVer)
	}
}

// analyzeServerHello parses a TLS ServerHello handshake message.
//
// Wire format:
//
//	TLS record header : 5 bytes
//	Handshake header  : 4 bytes
//	server_version    : 2 bytes
//	random            : 32 bytes
//	session_id_length : 1 byte
//	session_id        : variable
//	cipher_suite      : 2 bytes (selected cipher)
//	compression_method: 1 byte
//	extensions_len    : 2 bytes
//	extensions        : variable
func (pc *PacketCapture) analyzeServerHello(payload []byte, discovery *models.CryptoDiscovery) {
	if discovery.RawMetadata == nil {
		discovery.RawMetadata = make(map[string]interface{})
	}
	discovery.RawMetadata["handshake_type"] = "ServerHello"
	discovery.Confidence = 0.9

	// Minimum: record(5) + handshake(4) + version(2) + random(32) + sid_len(1) + cipher(2) + comp(1) = 47
	if len(payload) < 47 {
		return
	}

	// Skip: record(5) + handshake(4) + version(2) + random(32) = offset 43
	offset := 43

	// session_id_length
	sidLen := int(payload[offset])
	offset++
	offset += sidLen

	if offset+2 > len(payload) {
		return
	}

	// Selected cipher suite
	suite := binary.BigEndian.Uint16(payload[offset : offset+2])
	offset += 2
	if name := tlsCipherName(suite); name != "" {
		discovery.CipherSuite = name
		discovery.RawMetadata["selected_cipher"] = name
		if kex := crypto.ParseKeyExchangeAlgorithm(name); kex != "" {
			discovery.RawMetadata["key_exchange_algorithm"] = kex
		}
	}

	// Skip compression method
	offset++

	// Parse extensions for supported_versions (actual TLS version in TLS 1.3)
	if offset+2 > len(payload) {
		return
	}
	extTotalLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2
	extEnd := offset + extTotalLen
	if extEnd > len(payload) {
		extEnd = len(payload)
	}

	version := parseSupportedVersionsExt(payload, offset, extEnd)
	if version != "" {
		discovery.Version = version
	} else {
		recVer := binary.BigEndian.Uint16(payload[9:11])
		discovery.Version = tlsVersionName(recVer)
	}

	// JA3S-style fingerprint: version (wire), cipher suite, extension type IDs (comma-separated), then MD5
	serverVersionWire := binary.BigEndian.Uint16(payload[9:11])
	var extIDs []string
	for o := offset; o+4 <= extEnd && o+4 <= len(payload); {
		extType := binary.BigEndian.Uint16(payload[o : o+2])
		extLen := int(binary.BigEndian.Uint16(payload[o+2 : o+4]))
		extIDs = append(extIDs, strconv.Itoa(int(extType)))
		o += 4 + extLen
	}
	ja3sParts := []string{strconv.Itoa(int(serverVersionWire)), strconv.Itoa(int(suite)), strings.Join(extIDs, "-")}
	ja3sStr := strings.Join(ja3sParts, ",")
	sum := md5.Sum([]byte(ja3sStr))
	discovery.RawMetadata["ja3s_fingerprint"] = hex.EncodeToString(sum[:])
}

// analyzeCertificate parses a TLS Certificate handshake message and extracts
// the leaf certificate's fingerprint and key metadata.
//
// Wire format (RFC 5246):
//
//	TLS record header     : 5 bytes
//	Handshake header      : 4 bytes
//	certificate_list_length: 3 bytes
//	For each cert: cert_length(3) + DER bytes
func (pc *PacketCapture) analyzeCertificate(payload []byte, discovery *models.CryptoDiscovery) {
	if discovery.RawMetadata == nil {
		discovery.RawMetadata = make(map[string]interface{})
	}
	discovery.RawMetadata["handshake_type"] = "Certificate"
	discovery.Confidence = 0.95

	// Skip record(5) + handshake header(4) = 9 bytes; cert_list_length is 3 bytes
	if len(payload) < 12 {
		return
	}
	offset := 9
	certListLen := int(payload[offset])<<16 | int(payload[offset+1])<<8 | int(payload[offset+2])
	offset += 3

	if certListLen <= 0 || offset+certListLen > len(payload) {
		return
	}

	// Parse the first (leaf) certificate
	if offset+3 > len(payload) {
		return
	}
	certLen := int(payload[offset])<<16 | int(payload[offset+1])<<8 | int(payload[offset+2])
	offset += 3

	if certLen <= 0 || offset+certLen > len(payload) {
		return
	}

	der := payload[offset : offset+certLen]
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return
	}

	// Fingerprint
	fp := sha256.Sum256(der)
	discovery.RawMetadata["cert_fingerprint_sha256"] = hex.EncodeToString(fp[:])
	discovery.RawMetadata["cert_subject"] = cert.Subject.String()
	discovery.RawMetadata["cert_issuer"] = cert.Issuer.String()
	discovery.RawMetadata["cert_not_after"] = cert.NotAfter.UTC().Format(time.RFC3339)
	discovery.RawMetadata["cert_not_before"] = cert.NotBefore.UTC().Format(time.RFC3339)
	discovery.RawMetadata["cert_key_algorithm"] = cert.PublicKeyAlgorithm.String()
	discovery.RawMetadata["cert_signature_algorithm"] = cert.SignatureAlgorithm.String()
	discovery.RawMetadata["certificate_pem"] = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	// Public key size
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		discovery.RawMetadata["cert_public_key_size"] = key.Size() * 8
	case *ecdsa.PublicKey:
		discovery.RawMetadata["cert_public_key_size"] = key.Curve.Params().BitSize
	}

	// Subject Alternative Names
	sans := make([]string, 0, len(cert.DNSNames)+len(cert.IPAddresses)+len(cert.EmailAddresses))
	sans = append(sans, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	sans = append(sans, cert.EmailAddresses...)
	if len(sans) > 0 {
		discovery.RawMetadata["cert_san"] = sans
	}
}

// parseSupportedVersionsExt scans TLS extensions in payload[start:end] for the
// supported_versions extension (type 0x002b) and returns the highest TLS version
// name found, or "" if the extension is not present.
func parseSupportedVersionsExt(payload []byte, start, end int) string {
	offset := start
	for offset+4 <= end && offset+4 <= len(payload) {
		extType := binary.BigEndian.Uint16(payload[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
		offset += 4

		if offset+extLen > end || offset+extLen > len(payload) {
			break
		}

		if extType == 0x002b && extLen >= 2 {
			// ServerHello: extension_data is a single selected version (2 bytes).
			if extLen == 2 {
				ver := binary.BigEndian.Uint16(payload[offset : offset+2])
				if name := tlsVersionName(ver); name != "" {
					return name
				}
			} else {
				// ClientHello: extension_data is:
				//   supported_versions_length (1 byte) + versions (2 bytes each).
				listLen := int(payload[offset])
				if listLen > 0 && listLen%2 == 0 && listLen+1 <= extLen {
					listStart := offset + 1
					listEnd := listStart + listLen
					var best uint16
					for i := listStart; i+1 < listEnd; i += 2 {
						ver := binary.BigEndian.Uint16(payload[i : i+2])
						if tlsVersionName(ver) != "" && ver > best {
							best = ver
						}
					}
					if best != 0 {
						return tlsVersionName(best)
					}
				}
			}
		}
		offset += extLen
	}
	return ""
}

// tlsVersionName maps a TLS numeric version to its human-readable name.
// This is intentionally separate from the active prober's getTLSVersion so the
// passive path never relies on the record-layer version field for 1.3 detection.
func tlsVersionName(ver uint16) string {
	switch ver {
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	default:
		return ""
	}
}

// tlsCipherName maps a TLS cipher suite ID to its IANA name.
// Covers suites commonly seen in practice; unlisted suites return "Unknown-0x...."
// (except EMPTY_RENEGOTIATION_INFO_SCSV 0x00FF which returns "").
func tlsCipherName(suite uint16) string {
	switch suite {
	case 0x0000:
		return "" // TLS_NULL_WITH_NULL_NULL — skip
	case 0x000A:
		return "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
	case 0x0016:
		return "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"
	case 0x002F:
		return "TLS_RSA_WITH_AES_128_CBC_SHA"
	case 0x0032:
		return "TLS_DHE_DSS_WITH_AES_128_CBC_SHA"
	case 0x0033:
		return "TLS_DHE_RSA_WITH_AES_128_CBC_SHA" // e.g. dh480.badssl.com (weak DH params are not visible in suite id alone)
	case 0x0035:
		return "TLS_RSA_WITH_AES_256_CBC_SHA"
	case 0x0038:
		return "TLS_DHE_DSS_WITH_AES_256_CBC_SHA"
	case 0x0039:
		return "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
	case 0x0067:
		return "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"
	case 0x006B:
		return "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"
	case 0x003C:
		return "TLS_RSA_WITH_AES_128_CBC_SHA256"
	case 0x003D:
		return "TLS_RSA_WITH_AES_256_CBC_SHA256"
	case 0x009C:
		return "TLS_RSA_WITH_AES_128_GCM_SHA256"
	case 0x009D:
		return "TLS_RSA_WITH_AES_256_GCM_SHA384"
	case 0xC013:
		return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
	case 0xC014:
		return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
	case 0xC027:
		return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
	case 0xC02B:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	case 0xC02C:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	case 0xC02F:
		return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case 0xC030:
		return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	case 0xCCA8:
		return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
	case 0xCCA9:
		return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
	case 0x1301:
		return "TLS_AES_128_GCM_SHA256"
	case 0x1302:
		return "TLS_AES_256_GCM_SHA384"
	case 0x1303:
		return "TLS_CHACHA20_POLY1305_SHA256"
	default:
		if suite != 0x00FF { // skip EMPTY_RENEGOTIATION_INFO_SCSV
			return fmt.Sprintf("Unknown-0x%04X", suite)
		}
		return ""
	}
}

// Helper functions
func getPortNumber(portStr string) int {
	n, err := strconv.Atoi(portStr)
	if err != nil {
		return 0
	}
	return n
}

func getProtocolFromPort(port int, enableSTARTTLS bool, starttlsPorts []int) string {
	switch port {
	case 443, 993, 995, 465, 587, 636, 5671, 8443, 853:
		// 443  HTTPS, 993 IMAPS, 995 POP3S, 465 SMTPS, 587 SMTP+STARTTLS
		// 636  LDAPS, 5671 AMQPS, 8443 alt-HTTPS, 853 DNS-over-TLS
		return "TLS"
	case 22:
		return "SSH"
	case 3389:
		return "TLS" // RDP uses TLS over TCP
	case 445:
		return "SMB"
	case 88:
		return "Kerberos"
	case 502:
		return "Modbus"
	case 802:
		return "TLS" // Modbus/TLS (RFC 8184) — TLS assembler handles cert + IEC 62351 classification
	case 102:
		// MMS / ICCP (IEC 61850 / TASE.2). Returning "MMS" makes the dispatch
		// route to the MMS assembler AND the TLS assembler — see analyzePacket.
		return "MMS"
	case 20000:
		return "DNP3"
	case 4840:
		return "OPC_UA"
	case 44818:
		return "EtherNet_IP"
	case 5094:
		return "HART_IP"
	case 500, 4500:
		// IKE (500), IKE NAT-T (4500) - UDP-only; must match ike_detector "IKE" for assessment
		return "IKE"
	case 25, 143, 110, 5432, 3306, 21, 5222, 389:
		// STARTTLS ports — plaintext protocols that may upgrade to TLS
		if enableSTARTTLS {
			return "STARTTLS"
		}
		return ""
	default:
		if enableSTARTTLS {
			for _, p := range starttlsPorts {
				if p == port {
					return "STARTTLS"
				}
			}
		}
		return ""
	}
}

// getUDPProtocolFromPort maps well-known UDP ports to protocol names.
func getUDPProtocolFromPort(port int) string {
	switch port {
	case 443:
		return "QUIC"
	case 500, 4500:
		return "IKE"
	case 51820:
		return "WireGuard"
	case 1194:
		return "OpenVPN"
	case 88:
		return "Kerberos"
	case 20000:
		return "DNP3"
	case 5094:
		return "HART_IP"
	}
	return ""
}

func generateDiscoveryID() string {
	return uuid.New().String()
}
