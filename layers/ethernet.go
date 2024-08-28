package layers

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
	payload   []byte
}

func (ef *EthernetFrame) String() string {
	ethType, _ := ef.NextLayer()
	return fmt.Sprintf(`Ethernet Frame:
- DstMAC: %s
- SrcMAC: %s
- EtherType: %s (%#04x)
- Payload: %d bytes 
%s`,
		ef.DstMAC,
		ef.SrcMAC,
		ethType,
		ef.EtherType,
		len(ef.payload),
		hex.Dump(ef.payload))
}

// Parse parses the given byte data into an Ethernet frame.
func (ef *EthernetFrame) Parse(data []byte) error {
	if len(data) < ethernetHeaderSize {
		return fmt.Errorf("did not read a complete Ethernet frame, only %d bytes read", len(data))
	}
	ef.DstMAC = net.HardwareAddr(data[0:6])
	ef.SrcMAC = net.HardwareAddr(data[6:12])
	ef.EtherType = binary.BigEndian.Uint16(data[12:14])
	ef.payload = data[ethernetHeaderSize:]
	return nil
}

// NextLayer returns the name and payload of the next layer protocol based on the EtherType field of the EthernetFrame.
func (ef *EthernetFrame) NextLayer() (string, []byte) {
	var layer string
	switch ef.EtherType {
	case 0x0800:
		layer = "IPv4"
	case 0x0806:
		layer = "ARP"
	case 0x86dd:
		layer = "IPv6"
	default:
		layer = ""
	}
	return layer, ef.payload
}
