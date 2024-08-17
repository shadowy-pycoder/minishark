package minishark

import (
	"encoding/binary"
	"fmt"
)

const headerSizeTCP = 20

type TCPSegment struct {
	SrcPort       uint16
	DstPort       uint16
	SeqNumber     uint32
	AckNumber     uint32
	DataOffset    uint8
	Reserved      uint8
	Flags         uint8
	WindowSize    uint16
	Checksum      uint16
	UrgentPointer uint16
	Options       []byte
}

func (t *TCPSegment) String() string {
	return fmt.Sprintf(`TCP Segment:
- SrcPort: %d
- DstPort: %d
- Sequence Number: %d
- Acknowledgment Number: %d
- Data Offset: %d
- Reserved: %d
- Flags: %s (%#08b)
- Window Size: %d
- Checksum: %#04x
- Urgent Pointer: %d
- Options: (%d bytes) %x
`,
		t.SrcPort,
		t.DstPort,
		t.SeqNumber,
		t.AckNumber,
		t.DataOffset,
		t.Reserved,
		t.flags(),
		t.Flags,
		t.WindowSize,
		t.Checksum,
		t.UrgentPointer,
		len(t.Options),
		t.Options,
	)
}

func (t *TCPSegment) Parse(data []byte) error {
	if len(data) < headerSizeTCP {
		return fmt.Errorf("minimum header size for TCP is %d bytes, got %d bytes", headerSizeTCP, len(data))
	}
	t.SrcPort = binary.BigEndian.Uint16(data[0:2])
	t.DstPort = binary.BigEndian.Uint16(data[2:4])
	t.SeqNumber = binary.BigEndian.Uint32(data[4:8])
	t.AckNumber = binary.BigEndian.Uint32(data[8:12])
	offsetReservedFlags := binary.BigEndian.Uint16(data[12:14])
	t.DataOffset = uint8(offsetReservedFlags >> 12)
	t.Reserved = uint8((offsetReservedFlags >> 8) & 15)
	t.Flags = uint8(offsetReservedFlags & (1<<8 - 1))
	t.WindowSize = binary.BigEndian.Uint16(data[14:16])
	t.Checksum = binary.BigEndian.Uint16(data[16:18])
	t.UrgentPointer = binary.BigEndian.Uint16(data[18:headerSizeTCP])
	t.Options = data[headerSizeTCP:]
	return nil
}

func (t *TCPSegment) NextLayer() string {
	return ""
}

func (t *TCPSegment) flags() string {
	return fmt.Sprintf("CWR %d ECE %d URG %d ACK %d PSH %d RST %d SYN %d FIN %d",
		(t.Flags>>7)&1,
		(t.Flags>>6)&1,
		(t.Flags>>5)&1,
		(t.Flags>>4)&1,
		(t.Flags>>3)&1,
		(t.Flags>>2)&1,
		(t.Flags>>1)&1,
		t.Flags&1)
}
