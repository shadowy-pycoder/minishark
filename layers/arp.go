package layers

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
)

const headerSizeARP = 28

// The Address Resolution Protocol (ARP) is a communication protocol
// used for discovering the link layer address, such as a MAC address,
// associated with a given internet layer address, typically an IPv4 address.
// Defined in RFC 826.
type ARPPacket struct {
	HardwareType     uint16 // Network link protocol type.
	ProtocolType     uint16 // Internetwork protocol for which the ARP request is intended.
	ProtocolTypeDesc string // Internetwork protocol description.
	Hlen             uint8  // Length (in octets) of a hardware address.
	Plen             uint8  // Length (in octets) of internetwork addresses.
	Op               uint16 // Specifies the operation that the sender is performing.
	OpDesc           string // Operation description.
	// Media address of the sender. In an ARP request this field is used to indicate
	// the address of the host sending the request. In an ARP reply this field is used
	// to indicate the address of the host that the request was looking for.
	SenderMAC net.HardwareAddr
	SenderIP  netip.Addr // Internetwork address of the sender.
	// Media address of the intended receiver. In an ARP request this field is ignored.
	// In an ARP reply this field is used to indicate the address of the host that originated the ARP request.
	TargetMAC net.HardwareAddr
	TargetIP  netip.Addr // Internetwork address of the intended receiver.
}

func (ap *ARPPacket) String() string {
	return fmt.Sprintf(`%s
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
		ap.Summary(),
		ap.HardwareType,
		ap.ProtocolTypeDesc,
		ap.ProtocolType,
		ap.Hlen,
		ap.Plen,
		ap.OpDesc,
		ap.Op,
		ap.SenderMAC,
		ap.SenderIP,
		ap.TargetMAC,
		ap.TargetIP,
	)
}

func (ap *ARPPacket) Summary() string {
	var message string
	switch ap.OpDesc {
	case "request":
		message = fmt.Sprintf("ARP Packet: (%s) Who has %s? Tell %s", ap.OpDesc, ap.TargetIP, ap.SenderIP)
	case "reply":
		message = fmt.Sprintf("ARP Packet: (%s) %s at %s", ap.OpDesc, ap.SenderIP, ap.SenderMAC)
	default:
		message = fmt.Sprintf("ARP Packet: (%s)", ap.OpDesc)
	}
	return message
}

// Parse parses the given ARP packet data into the ARPPacket struct.
func (ap *ARPPacket) Parse(data []byte) error {
	if len(data) < headerSizeARP {
		return fmt.Errorf("minimum header size for ARP is %d bytes, got %d bytes", headerSizeARP, len(data))
	}
	ap.HardwareType = binary.BigEndian.Uint16(data[0:2])
	ap.ProtocolType = binary.BigEndian.Uint16(data[2:4])
	ap.ProtocolTypeDesc = ptypedesc(ap.ProtocolType)
	ap.Hlen = data[4]
	ap.Plen = data[5]
	ap.Op = binary.BigEndian.Uint16(data[6:8])
	ap.OpDesc = opdesc(ap.Op)
	hoffset := 8 + ap.Hlen
	ap.SenderMAC = net.HardwareAddr(data[8:hoffset])
	poffset := hoffset + ap.Plen
	var ok bool
	ap.SenderIP, ok = netip.AddrFromSlice(data[hoffset:poffset])
	if !ok {
		return fmt.Errorf("failed parsing sender IP address")
	}
	ap.TargetMAC = net.HardwareAddr(data[poffset : poffset+ap.Hlen])
	ap.TargetIP, ok = netip.AddrFromSlice(data[poffset+ap.Hlen : poffset+ap.Hlen+ap.Plen])
	if !ok {
		return fmt.Errorf("failed parsing target IP address")
	}
	return nil
}

func (ap *ARPPacket) NextLayer() (string, []byte) {
	return "", nil
}

func ptypedesc(pt uint16) string {
	var proto string
	switch pt {
	case 0x0800:
		proto = "IPv4"
	case 0x86dd:
		proto = "IPv6"
	default:
		proto = "Unknown"
	}
	return proto
}

func opdesc(op uint16) string {
	var opdesc string
	switch op {
	case 1:
		opdesc = "request"
	case 2:
		opdesc = "reply"
	default:
		opdesc = "Unknown"
	}
	return opdesc
}
