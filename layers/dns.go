package layers

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
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
%s
`,
		d.TransactionID,
		d.Flags,
		d.flags(),
		d.Questions,
		d.AnswerRRs,
		d.AuthorityRRs,
		d.AdditionalRRs,
		d.rrecords(),
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
	var flags string
	opcode := (d.Flags >> 11) & 15
	// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5
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
	qr := d.Flags >> 15
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
		// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
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
			rcodes = "Server Not Authoritative for zone"
		case 10:
			rcodes = "Name not contained in zone"
		case 11:
			rcodes = "DSO-TYPE Not Implemented"
		case 16:
			rcodes = "Bad OPT Version/TSIG Signature Failure"
		case 17:
			rcodes = "Key not recognizede"
		case 18:
			rcodes = "Signature out of time window"
		case 19:
			rcodes = "Bad TKEY Mode"
		case 20:
			rcodes = "Duplicate key name"
		case 21:
			rcodes = "Algorithm not supported"
		case 22:
			rcodes = "Bad Truncation"
		case 23:
			rcodes = "Bad/missing Server Cookie"
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

// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-2
func (d *DNSMessage) className(cls uint16) string {
	var cname string
	switch cls {
	case 0:
		cname = "Reserved"
	case 1:
		cname = "IN"
	case 3:
		cname = "CH"
	case 4:
		cname = "HS"
	default:
		cname = "Unknown"
	}
	return cname
}

// extractDomain extracts the DNS domain name from the given byte slice.
//
// The domain name is parsed according to RFC 1035 section 4.1.
func (d *DNSMessage) extractDomain(tail []byte) (string, []byte) {
	// see https://brunoscheufler.com/blog/2024-05-12-building-a-dns-message-parser#domain-names
	var domainName string
	for {
		blen := tail[0]
		if blen>>6 == 0b11 {
			// compressed message offset is 14 bits according to RFC 1035 section 4.1.4
			offset := binary.BigEndian.Uint16(tail[0:2])&(1<<14-1) - headerSizeDNS
			part, _ := d.extractDomain(d.payload[offset:]) // TODO: iterative approach
			domainName += part
			tail = tail[2:]
			break
		}
		tail = tail[1:]
		if blen == 0 {
			break
		}
		domainName += bytesToStr(tail[0:blen])
		domainName += "."

		tail = tail[blen:]
	}
	return strings.TrimRight(domainName, "."), tail
}

// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
func (d *DNSMessage) parseRData(typ uint16, tail []byte, rdl int) (string, string, []byte) {
	var (
		rdata    string
		typename string
	)
	switch typ {
	case 1:
		typename = "A"
		addr, _ := netip.AddrFromSlice(tail[0:rdl])
		rdata = fmt.Sprintf("Address: %s", addr)
	case 2:
		typename = "NS"
		domain, _ := d.extractDomain(tail)
		rdata = fmt.Sprintf("%s: %s", typename, domain)
	case 5:
		typename = "CNAME"
		domain, _ := d.extractDomain(tail)
		rdata = fmt.Sprintf("%s: %s", typename, domain)
	case 6:
		typename = "SOA"
		var (
			primary string
			mailbox string
		)
		ttail := tail
		primary, ttail = d.extractDomain(ttail)
		mailbox, ttail = d.extractDomain(ttail)
		serial := binary.BigEndian.Uint32(ttail[0:4])
		refresh := binary.BigEndian.Uint32(ttail[4:8])
		retry := binary.BigEndian.Uint32(ttail[8:12])
		expire := binary.BigEndian.Uint32(ttail[12:16])
		min := binary.BigEndian.Uint32(ttail[16:20])
		rdata = fmt.Sprintf(`Primary name server: %s 
    - Responsible authority's mailbox: %s
    - Serial number: %d
    - Refresh interval: %d
    - Retry interval: %d
    - Expire limit: %d
    - Minimum TTL: %d`,
			primary, mailbox, serial, refresh, retry, expire, min)
	case 15:
		typename = "MX"
		preference := binary.BigEndian.Uint16(tail[0:2])
		domain, _ := d.extractDomain(tail[2:rdl])
		rdata = fmt.Sprintf("%s: preference %d %s", typename, preference, domain)
	case 16:
		typename = "TXT"
		rdata = fmt.Sprintf("%s: %s", typename, tail[:rdl])
	case 28:
		typename = "AAAA"
		addr, _ := netip.AddrFromSlice(tail[0:rdl])
		rdata = fmt.Sprintf("Address: %s", addr)
	case 41:
		typename = "OPT"
	case 65:
		typename = "HTTPS" // TODO: add proper parsing
		rdata = fmt.Sprintf("%s: %d bytes", typename, rdl)
	default:
		rdata = fmt.Sprintf("Unknown: %d bytes", rdl)
	}
	return typename, rdata, tail[rdl:]
}

func (d *DNSMessage) parseQuery(tail []byte) (string, []byte) {
	var domain string
	domain, tail = d.extractDomain(tail)
	typ := binary.BigEndian.Uint16(tail[0:2])
	typename, _, _ := d.parseRData(typ, tail, 0)
	class := binary.BigEndian.Uint16(tail[2:4])
	cname := d.className(class)
	tail = tail[4:]
	return fmt.Sprintf(`  - %s: 
    - Name: %s
    - Type: %s (%d)
    - Class: %s (%d)
`, domain, domain, typename, typ, cname, class), tail
}

func (d *DNSMessage) parseRR(tail []byte) (string, []byte) {
	var domain string
	domain, tail = d.extractDomain(tail)
	typ := binary.BigEndian.Uint16(tail[0:2])
	class := binary.BigEndian.Uint16(tail[2:4])
	cname := d.className(class)
	ttl := binary.BigEndian.Uint32(tail[4:8])
	rdl := int(binary.BigEndian.Uint16(tail[8:10]))
	var (
		typename string
		rdata    string
	)
	typename, rdata, tail = d.parseRData(typ, tail[10:], rdl)
	return fmt.Sprintf(`  - %s:     
    - Name: %s
    - Type: %s (%d)
    - Class: %s (%d)
    - TTL: %d
    - Data Length: %d
    - %s
`, domain, domain, typename, typ, cname, class, ttl, rdl, rdata), tail
}

func (d *DNSMessage) parseRoot(tail []byte) (string, []byte) {
	domain := "Root"
	tail = tail[1:]
	typ := binary.BigEndian.Uint16(tail[0:2])
	ups := binary.BigEndian.Uint16(tail[2:4])
	hb := tail[4]
	ednsv := tail[5]
	zres := binary.BigEndian.Uint16(tail[6:8])
	rdl := int(binary.BigEndian.Uint16(tail[8:10]))
	var typename string
	typename, _, tail = d.parseRData(typ, tail[10:], rdl)
	return fmt.Sprintf(`  - %s: 
    - Name: %s
    - Type: %s (%d)
    - UDP payload size: %d
    - Higher bits in extended RCODE: %#02x
    - EDNS0 version: %d
    - Z: %d
    - Data Length: %d
`, domain, domain, typename, typ, ups, hb, ednsv, zres, rdl), tail
}

func (d *DNSMessage) rrecords() string {
	var (
		sb   strings.Builder
		rec  string
		tail = d.payload
	)
	if d.Questions > 0 {
		sb.WriteString("- Queries:\n")
		for range d.Questions {
			rec, tail = d.parseQuery(tail)
			sb.WriteString(rec)
		}
	}
	if d.AnswerRRs > 0 {
		sb.WriteString("- Answers:\n")
		for range d.AnswerRRs {
			rec, tail = d.parseRR(tail)
			sb.WriteString(rec)
		}
	}
	if d.AuthorityRRs > 0 {
		sb.WriteString("- Authoritative nameservers:\n")
		for range d.AuthorityRRs {
			rec, tail = d.parseRR(tail)
			sb.WriteString(rec)
		}
	}
	if d.AdditionalRRs > 0 {
		sb.WriteString("- Additional records:\n")
		for range d.AdditionalRRs {
			if tail[0] != 0 {
				rec, tail = d.parseRR(tail)
				sb.WriteString(rec)
			} else {
				rec, tail = d.parseRoot(tail)
				sb.WriteString(rec)
			}
		}
	}
	return sb.String()
}
