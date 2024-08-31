package layers

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unsafe"
)

const headerSizeDNS = 12

type DNSMessage struct {
	TransactionID uint16 // Used for matching response to queries.
	Flags         uint16 // Flags specify the requested operation and a response code.
	Questions     uint16 // Count of entries in the queries section.
	AnswerRRs     uint16 // Count of entries in the answers section.
	AuthorityRRs  uint16 // Count of entries in the authority section.
	AdditionalRRs uint16 // Count of entries in the additional section.
	payload       []byte
}

func (d *DNSMessage) String() string {
	return fmt.Sprintf(`DNS Message:
- Transaction ID: %#04x
- Flags: %#04x
%s
- Questions: %d
- Answer RRs: %d
- Authority RRs: %d
- Additional RRs: %d
- Payload: %d bytes
%s
`,
		d.TransactionID,
		d.Flags,
		d.flags(),
		d.Questions,
		d.AnswerRRs,
		d.AuthorityRRs,
		d.AdditionalRRs,
		len(d.payload),
		d.queries(),
	)
}

// Parse parses the given byte data into a DNSMessage struct.
func (d *DNSMessage) Parse(data []byte) error {
	if len(data) < headerSizeDNS {
		return fmt.Errorf("minimum header size for DNS is %d bytes, got %d bytes", headerSizeDNS, len(data))
	}
	d.TransactionID = binary.BigEndian.Uint16(data[0:2])
	d.Flags = binary.BigEndian.Uint16(data[2:4])
	d.Questions = binary.BigEndian.Uint16(data[4:6])
	d.AnswerRRs = binary.BigEndian.Uint16(data[6:8])
	d.AuthorityRRs = binary.BigEndian.Uint16(data[8:10])
	d.AdditionalRRs = binary.BigEndian.Uint16(data[10:headerSizeDNS])
	d.payload = data[headerSizeDNS:]
	return nil
}

func (d *DNSMessage) NextLayer() (string, []byte) {
	return "", nil
}

func (d *DNSMessage) flags() string {
	// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
	var flags string
	opcode := (d.Flags >> 11) & 15
	var opcodes string
	switch opcode {
	case 0:
		opcodes = "Standard query"
	case 1:
		opcodes = "Inverse query"
	case 2:
		opcodes = "Server status request"
	case 4:
		opcodes = "Notify"
	case 5:
		opcodes = "Update"
	case 6:
		opcodes = "Stateful operation"
	default:
		opcodes = "Unknown"
	}
	tc := (d.Flags >> 9) & 1
	rd := (d.Flags >> 8) & 1
	z := (d.Flags >> 6) & 1
	na := (d.Flags >> 4) & 1
	qr := (d.Flags >> 15) & 1
	var qrs string
	switch qr {
	case 0:
		qrs = "query"
		flags = fmt.Sprintf(`  - Response: Message is a %s (%d)
  - Opcode: %s (%d)
  - Truncated: %d
  - Recursion desired: %d
  - Reserved: %d
  - Non-authenticated data: %d`, qrs, qr, opcodes, opcode, tc, rd, z, na)
	case 1:
		qrs = "reply"
		a := (d.Flags >> 10) & 1
		ra := (d.Flags >> 7) & 1
		aa := (d.Flags >> 5) & 1
		rcode := d.Flags & 15
		var rcodes string
		switch rcode {
		case 0:
			rcodes = "No error"
		case 1:
			rcodes = "Format error"
		case 2:
			rcodes = "Server failed to complete the DNS request"
		case 3:
			rcodes = "Domain name does not exist"
		case 4:
			rcodes = "Function not implemented"
		case 5:
			rcodes = "The server refused to answer for the query"
		case 6:
			rcodes = "Name that should not exist, does exist"
		case 7:
			rcodes = "RRset that should not exist, does exist"
		case 8:
			rcodes = "Server not authoritative for the zone"
		case 9:
			rcodes = "Name not in zone"
		default:
			rcodes = "Unknown"
		}
		flags = fmt.Sprintf(`  - Response: Message is a %s (%d)
  - Opcode: %s (%d)
  - Authoritative: %d
  - Truncated: %d
  - Recursion desired: %d
  - Recursion available: %d
  - Reserved: %d
  - Answer authenticated: %d
  - Non-authenticated data: %d
  - Reply code: %s (%d)`, qrs, qr, opcodes, opcode, a, tc, rd, ra, z, aa, na, rcodes, rcode)
	}
	return flags
}

func bytesToStr(myBytes []byte) string {
	return unsafe.String(unsafe.SliceData(myBytes), len(myBytes))
}

func extractDomain(data []byte, offset int) (string, int) {
	var parts []string
	for {
		blen := int(data[offset])
		offset++
		if blen == 0 {
			break
		}
		if blen == 0xc0 {
			offset = int(data[offset]) - headerSizeDNS
			blen = int(data[offset])
			offset++
		}
		parts = append(parts, bytesToStr(data[offset:offset+blen]))
		offset += blen
	}
	return strings.Join(parts, "."), offset
}

func (d *DNSMessage) queries() string {
	var (
		sb     strings.Builder
		offset int
	)
	if d.Questions > 0 {
		sb.WriteString("- Queries:\n")
		for range d.Questions {
			var domain string
			domain, offset = extractDomain(d.payload, offset)
			typ := binary.BigEndian.Uint16(d.payload[offset : offset+2])
			offset += 2
			class := binary.BigEndian.Uint16(d.payload[offset : offset+2])
			offset += 2
			// TODO: add type and class description https://en.wikipedia.org/wiki/List_of_DNS_record_types
			sb.WriteString(fmt.Sprintf("  %s: type %d class %d\n", domain, typ, class))
		}
	}
	if d.AnswerRRs > 0 {
		sb.WriteString("- Answers:\n")
		for range d.AnswerRRs {
			no := binary.BigEndian.Uint16(d.payload[offset : offset+2])
			offset += 2
			domain, _ := extractDomain(d.payload, int(no&0xFF)-headerSizeDNS)
			typ := binary.BigEndian.Uint16(d.payload[offset : offset+2])
			offset += 2
			class := binary.BigEndian.Uint16(d.payload[offset : offset+2])
			offset += 2
			ttl := binary.BigEndian.Uint32(d.payload[offset : offset+4])
			offset += 4
			rdl := int(binary.BigEndian.Uint16(d.payload[offset : offset+2]))
			offset += 2
			//rdata := d.payload[offset : offset+rdl]
			offset += rdl
			sb.WriteString(fmt.Sprintf("  %s: type %d class %d ttl %d rdl %d\n", domain, typ, class, ttl, rdl))
		}
	}
	if d.AuthorityRRs > 0 {

	}
	if d.AdditionalRRs > 0 {

	}
	return sb.String()
}
