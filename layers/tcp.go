package layers

import (
	"encoding/binary"
	"fmt"
)

const headerSizeTCP = 20

type TCPFlags struct {
	Raw uint8
	CWR uint8
	ECE uint8
	URG uint8
	ACK uint8
	PSH uint8
	RST uint8
	SYN uint8
	FIN uint8
}

func (t *TCPFlags) String() string {
	return fmt.Sprintf("CWR %d ECE %d URG %d ACK %d PSH %d RST %d SYN %d FIN %d (%#08b)",
		t.CWR,
		t.ECE,
		t.URG,
		t.ACK,
		t.PSH,
		t.RST,
		t.SYN,
		t.FIN,
		t.Raw)
}

func newTCPFlags(flags uint8) *TCPFlags {
	return &TCPFlags{
		Raw: flags,
		CWR: (flags >> 7) & 1,
		ECE: (flags >> 6) & 1,
		URG: (flags >> 5) & 1,
		ACK: (flags >> 4) & 1,
		PSH: (flags >> 3) & 1,
		RST: (flags >> 2) & 1,
		SYN: (flags >> 1) & 1,
		FIN: flags & 1}
}

// TCP protocol is described in RFC 761.
type TCPSegment struct {
	SrcPort uint16 // Identifies the sending port.
	DstPort uint16 // Identifies the receiving port.
	// If the SYN flag is set (1), then this is the initial sequence number. The sequence number of the actual
	// first data byte and the acknowledged number in the corresponding ACK are then this sequence number plus 1.
	// If the SYN flag is unset (0), then this is the accumulated sequence number of the first data byte of this
	// segment for the current session.
	SeqNumber uint32
	// If the ACK flag is set, the value is the next sequence number that the sender of the ACK is expecting.
	AckNumber  uint32
	DataOffset uint8     // 4 bits specifies the size of the TCP header in 32-bit words.
	Reserved   uint8     // 4 bits reserved for future use and should be set to zero.
	Flag       *TCPFlags // Contains 8 1-bit flags (control bits)
	// The size of the receive window, which specifies the number of window size units[b] that the sender of
	// this segment is currently willing to receive.
	WindowSize uint16
	// The 16-bit checksum field is used for error-checking of the TCP header, the payload and an IP pseudo-header.
	Checksum uint16
	// If the URG flag is set, then this 16-bit field is an offset from the sequence number
	// indicating the last urgent data byte.
	UrgentPointer uint16
	Options       []byte // The length of this field is determined by the data offset field.
	payload       []byte
}

func (t *TCPSegment) String() string {
	return fmt.Sprintf(`%s
- SrcPort: %d
- DstPort: %d
- Sequence Number: %d
- Acknowledgment Number: %d
- Data Offset: %d
- Reserved: %d
- Flags: %s
- Window Size: %d
- Checksum: %#04x
- Urgent Pointer: %d
- Options: (%d bytes) %x
- Payload: %d bytes
`,
		t.Summary(),
		t.SrcPort,
		t.DstPort,
		t.SeqNumber,
		t.AckNumber,
		t.DataOffset,
		t.Reserved,
		t.Flag,
		t.WindowSize,
		t.Checksum,
		t.UrgentPointer,
		len(t.Options),
		t.Options,
		len(t.payload),
	)
}

func (t *TCPSegment) Summary() string {
	return fmt.Sprintf("TCP Segment: Src Port: %d Dst Port: %d Len: %d", t.SrcPort, t.DstPort, len(t.payload))
}

// Parse parses the given byte data into a TCPSegment struct.
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
	t.Flag = newTCPFlags(uint8(offsetReservedFlags & (1<<8 - 1)))
	t.WindowSize = binary.BigEndian.Uint16(data[14:16])
	t.Checksum = binary.BigEndian.Uint16(data[16:18])
	t.UrgentPointer = binary.BigEndian.Uint16(data[18:headerSizeTCP])
	t.Options = data[headerSizeTCP : t.DataOffset<<2]
	t.payload = data[t.DataOffset<<2:]
	return nil
}

func (t *TCPSegment) NextLayer() (string, []byte) {
	return nextAppLayer(t.SrcPort, t.DstPort), t.payload
}
