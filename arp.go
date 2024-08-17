package minishark

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
)

const headerSizeARP = 28

type ARPPacket struct {
	HardwareType uint16
	ProtocolType uint16
	Hlen         uint8
	Plen         uint8
	Op           uint16
	SenderMAC    net.HardwareAddr
	SenderIP     netip.Addr
	TargetMAC    net.HardwareAddr
	TargetIP     netip.Addr
}

func (ap *ARPPacket) String() string {
	return fmt.Sprintf(`ARP Packet:
- Hardware Type: %d
- Protocol Type: %s (%#04x)
- HLen: %d
- PLen: %d 
- Operation: %s (%d)
- Sender MAC Address: %s
- Sender IP Address: %s
- Target MAC Address: %s
- Target IP Address: %s
`,
		ap.HardwareType,
		ap.ptype(),
		ap.ProtocolType,
		ap.Hlen,
		ap.Plen,
		ap.operation(),
		ap.Op,
		ap.SenderMAC,
		ap.SenderIP,
		ap.TargetMAC,
		ap.TargetIP,
	)
}

func (ap *ARPPacket) Parse(data []byte) error {
	if len(data) < headerSizeARP {
		return fmt.Errorf("minimum header size for ARP is %d bytes, got %d bytes", headerSizeARP, len(data))
	}
	ap.HardwareType = binary.BigEndian.Uint16(data[0:2])
	ap.ProtocolType = binary.BigEndian.Uint16(data[2:4])
	ap.Hlen = data[4]
	ap.Plen = data[5]
	ap.Op = binary.BigEndian.Uint16(data[6:8])
	hoffset := 8 + ap.Hlen
	ap.SenderMAC = net.HardwareAddr(data[8:hoffset])
	poffset := hoffset + ap.Plen
	ap.SenderIP, _ = netip.AddrFromSlice(data[hoffset:poffset])
	ap.TargetMAC = net.HardwareAddr(data[poffset : poffset+ap.Hlen])
	ap.TargetIP, _ = netip.AddrFromSlice(data[poffset+ap.Hlen : poffset+ap.Hlen+ap.Plen])
	return nil
}

func (ap *ARPPacket) ptype() string {
	var proto string
	switch ap.ProtocolType {
	case 0x0800:
		proto = "IPv4"
	case 0x86dd:
		proto = "IPv6"
	default:
		proto = "Unknown"
	}
	return proto
}

func (ap *ARPPacket) operation() string {
	var op string
	switch ap.Op {
	case 1:
		op = "request"
	case 2:
		op = "reply"
	default:
		op = "Unknown"
	}
	return op
}
