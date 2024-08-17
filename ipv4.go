package minishark

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

const headerSizeIPv4 = 20

type IPv4Packet struct {
	Version        uint8 // 4 bits version field (for IPv4, this is always equal to 4)
	IHL            uint8 // 4 bits size of header (number of 32-bit words)
	DSCP           uint8 // 6 bits field (specifies differentiated services)
	ECN            uint8 // 2 bits field (end-to-end notification of network congestion without dropping packets)
	TotalLength    uint16
	Identification uint16
	Flags          uint8  // 3 bits field (used to control or identify fragments)
	FragmentOffset uint16 // 13 bits (offset of a particular fragment)
	TTL            uint8
	Protocol       uint8
	HeaderChecksum uint16
	SrcIP          netip.Addr
	DstIP          netip.Addr
	Options        []byte // if ihl > 5
	Payload        []byte
}

func (p *IPv4Packet) String() string {
	return fmt.Sprintf(`IPv4 Packet:
- Version: %d
- IHL: %d
- DSCP: %s (%#06b)
- ECN: %#02b
- Total Length: %d
- Identification: %#04x
- Flags: %s
- Fragment Offset: %d
- TTL: %d
- Protocol: %s (%d)
- Header Checksum: %#04x
- SrcIP: %s
- DstIP: %s
- Options: %v
- Payload: (%d bytes) %x
`,
		p.Version,
		p.IHL,
		p.dscp(),
		p.DSCP,
		p.ECN,
		p.TotalLength,
		p.Identification,
		p.flags(),
		p.FragmentOffset,
		p.TTL,
		p.NextLayer(),
		p.Protocol,
		p.HeaderChecksum,
		p.SrcIP,
		p.DstIP,
		p.Options,
		len(p.Payload),
		p.Payload)
}

func (p *IPv4Packet) Parse(data []byte) error {
	if len(data) < headerSizeIPv4 {
		return fmt.Errorf("minimum header size for IPv4 is %d bytes, got %d bytes", headerSizeIPv4, len(data))
	}
	versionIHL := data[0]
	p.Version = versionIHL >> 4
	p.IHL = versionIHL & 15
	dscpECN := data[1]
	p.DSCP = dscpECN >> 2
	p.ECN = dscpECN & 3
	p.TotalLength = binary.BigEndian.Uint16(data[2:4])
	p.Identification = binary.BigEndian.Uint16(data[4:6])
	flagsOffset := binary.BigEndian.Uint16(data[6:8])
	p.Flags = uint8(flagsOffset >> 13)
	p.FragmentOffset = flagsOffset & (1<<13 - 1)
	p.TTL = data[8]
	p.Protocol = data[9]
	p.HeaderChecksum = binary.BigEndian.Uint16(data[10:12])
	p.SrcIP, _ = netip.AddrFromSlice(data[12:16])
	p.DstIP, _ = netip.AddrFromSlice(data[16:headerSizeIPv4])
	if p.IHL > 5 {
		offset := headerSizeIPv4 + ((p.IHL - 5) << 2)
		p.Options = data[headerSizeIPv4:offset]
		p.Payload = data[offset:]
	} else {
		p.Payload = data[headerSizeIPv4:]
	}
	return nil
}

func (p *IPv4Packet) NextLayer() string {
	// https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
	var proto string
	switch p.Protocol {
	case 1:
		proto = "ICMP"
	case 6:
		proto = "TCP"
	case 17:
		proto = "UDP"
	default:
		proto = "Unknown"
	}
	return proto
}

func (p *IPv4Packet) dscp() string {
	// https://en.wikipedia.org/wiki/Differentiated_services
	var dscp string
	switch p.DSCP {
	case 0:
		dscp = "Standard (DF)"
	case 1:
		dscp = "Lower-effort (LE)"
	case 48:
		dscp = "Network control (CS6)"
	case 46:
		dscp = "Telephony (EF)"
	case 40:
		dscp = "Signaling (CS5)"
	case 34, 36, 38:
		dscp = "Multimedia conferencing (AF41, AF42, AF43)"
	case 32:
		dscp = "Real-time interactive (CS4)"
	case 26, 28, 30:
		dscp = "Multimedia streaming (AF31, AF32, AF33)"
	case 24:
		dscp = "Broadcast video (CS3)"
	case 18, 20, 22:
		dscp = "Low-latency data (AF21, AF22, AF23)"
	case 16:
		dscp = "OAM (CS2)"
	case 10, 12, 14:
		dscp = "High-throughput data (AF11, AF12, AF13)"
	default:
		dscp = "Unknown"
	}
	return dscp
}

func (p *IPv4Packet) flags() string {
	return fmt.Sprintf("Reserved %d DF %d MF %d", (p.Flags>>2)&1, (p.Flags>>1)&1, p.Flags&1)
}
