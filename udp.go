package minishark

import (
	"encoding/binary"
	"fmt"
)

const headerSizeUDP = 8

type UDPSegment struct {
	SrcPort   uint16
	DstPort   uint16
	UDPLength uint16
	Checksum  uint16
	Payload   []byte
}

func (u *UDPSegment) String() string {
	return fmt.Sprintf(`UDP Segment:
- SrcPort: %d
- DstPort: %d
- UDP Length: %d
- Checksum: %#04x
- Payload: (%d bytes) %x
`,
		u.SrcPort,
		u.DstPort,
		u.UDPLength,
		u.Checksum,
		len(u.Payload),
		u.Payload,
	)
}

func (u *UDPSegment) Parse(data []byte) error {
	if len(data) < headerSizeUDP {
		return fmt.Errorf("minimum header size for UDP is %d bytes, got %d bytes", headerSizeUDP, len(data))
	}
	u.SrcPort = binary.BigEndian.Uint16(data[0:2])
	u.DstPort = binary.BigEndian.Uint16(data[2:4])
	u.UDPLength = binary.BigEndian.Uint16(data[4:6])
	u.Checksum = binary.BigEndian.Uint16(data[6:headerSizeUDP])
	u.Payload = data[headerSizeUDP:]
	return nil
}

func (u *UDPSegment) NextLayer() string {
	return ""
}
