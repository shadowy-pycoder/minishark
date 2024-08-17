package minishark

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
)

const ethernetHeaderSize = 14

type EthernetFrame struct {
	DstMAC    net.HardwareAddr
	SrcMAC    net.HardwareAddr
	EtherType uint16
	Payload   []byte
}

func (ef *EthernetFrame) String() string {
	return fmt.Sprintf(`Ethernet Frame:
- DstMAC: %s
- SrcMAC: %s
- EtherType: %s (%#04x)
- Payload: (%d bytes) %x 
%s
`,
		ef.DstMAC,
		ef.SrcMAC,
		ef.NextLayer(),
		ef.EtherType,
		len(ef.Payload),
		ef.Payload,
		hex.Dump(ef.Payload))
}

// Parse parses the given byte data into an Ethernet frame.
func (ef *EthernetFrame) Parse(data []byte) error {
	if len(data) < ethernetHeaderSize {
		return fmt.Errorf("did not read a complete Ethernet frame, only %d bytes read", len(data))
	}
	ef.DstMAC = net.HardwareAddr(data[0:6])
	ef.SrcMAC = net.HardwareAddr(data[6:12])
	ef.EtherType = binary.BigEndian.Uint16(data[12:14])
	ef.Payload = data[ethernetHeaderSize:]
	return nil
}

func (ef *EthernetFrame) NextLayer() string {
	var ets string
	switch ef.EtherType {
	case 0x0800:
		ets = "IPv4"
	case 0x0806:
		ets = "ARP"
	case 0x86dd:
		ets = "IPv6"
	default:
		ets = "Unknown"
	}
	return ets
}
