package minishark

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
)

const ethernetHeaderSize = 14

// An Ethernet frame is a data link layer protocol data unit.
type EthernetFrame struct {
	DstMAC    net.HardwareAddr // MAC address of the destination device.
	SrcMAC    net.HardwareAddr // MAC address of the source device.
	EtherType uint16           // The protocol of the upper layer.
	Payload   []byte
}

func (ef *EthernetFrame) String() string {
	return fmt.Sprintf(`Ethernet Frame:
- DstMAC: %s
- SrcMAC: %s
- EtherType: %s (%#04x)
- Payload: (%d bytes) %x 
%s`,
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

// NextLayer returns the name of the next layer protocol based on the EtherType field of the EthernetFrame.
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
