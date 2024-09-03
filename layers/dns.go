package layers

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
)

const headerSizeDNS = 12

type DNSFlags struct {
	Raw        uint16
	QR         uint8  // Indicates if the message is a query (0) or a reply (1).
	QRDesc     string // Query (0) or Reply (1)
	OPCode     uint8  // https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5
	OPCodeDesc string
	AA         uint8 // Authoritative Answer, in a response, indicates if the DNS server is authoritative for the queried hostname.
	TC         uint8 // TrunCation, indicates that this message was truncated due to excessive length.
	RD         uint8 // Recursion Desired, indicates if the client means a recursive query.
	RA         uint8 // Recursion Available, in a response, indicates if the replying DNS server supports recursion.
	Z          uint8 // Zero, reserved for future use.
	AU         uint8 // Indicates if answer/authority portion was authenticated by the server.
	NA         uint8 // Indicates if non-authenticated data is accepatable.
	RCode      uint8 // https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
	RCodeDesc  string
}

func (df *DNSFlags) String() string {
	var flags string
	switch df.QR {
	case 0:
		flags = fmt.Sprintf(`  - Response: Message is a %s (%d)
  - Opcode: %s (%d)
  - Truncated: %d
  - Recursion desired: %d
  - Reserved: %d
  - Non-authenticated data: %d`, df.QRDesc, df.QR, df.OPCodeDesc, df.OPCode, df.TC, df.RD, df.Z, df.NA)
	case 1:
		flags = fmt.Sprintf(`  - Response: Message is a %s (%d)
  - Opcode: %s (%d)
  - Authoritative: %d
  - Truncated: %d
  - Recursion desired: %d
  - Recursion available: %d
  - Reserved: %d
  - Answer authenticated: %d
  - Non-authenticated data: %d
  - Reply code: %s (%d)`,
			df.QRDesc,
			df.QR,
			df.OPCodeDesc,
			df.OPCode,
			df.AA,
			df.TC,
			df.RD,
			df.RA,
			df.Z,
			df.AU,
			df.NA,
			df.RCodeDesc,
			df.RCode)
	}
	return flags
}

func newDNSFlags(flags uint16) *DNSFlags {
	qr := uint8(flags >> 15)
	opcode := uint8((flags >> 11) & 15)
	rcode := uint8(flags & 15)
	return &DNSFlags{
		Raw:        flags,
		QR:         qr,
		QRDesc:     qrdesc(qr),
		OPCode:     opcode,
		OPCodeDesc: opcdesc(opcode),
		AA:         uint8((flags >> 10) & 1),
		TC:         uint8((flags >> 9) & 1),
		RD:         uint8((flags >> 8) & 1),
		RA:         uint8((flags >> 7) & 1),
		Z:          uint8((flags >> 6) & 1),
		AU:         uint8((flags >> 5) & 1),
		NA:         uint8((flags >> 4) & 1),
		RCode:      rcode,
		RCodeDesc:  rcdesc(rcode),
	}
}

type DNSMessage struct {
	TransactionID uint16    // Used for matching response to queries.
	Flags         *DNSFlags // Flags specify the requested operation and a response code.
	Questions     uint16    // Count of entries in the queries section.
	AnswerRRs     uint16    // Count of entries in the answers section.
	AuthorityRRs  uint16    // Count of entries in the authority section.
	AdditionalRRs uint16    // Count of entries in the additional section.
	payload       []byte
}

func (d *DNSMessage) String() string {
	return fmt.Sprintf(`%s
- Transaction ID: %#04x
- Flags: %#04x
%s
- Questions: %d
- Answer RRs: %d
- Authority RRs: %d
- Additional RRs: %d
%s`,
		d.Summary(),
		d.TransactionID,
		d.Flags.Raw,
		d.Flags,
		d.Questions,
		d.AnswerRRs,
		d.AuthorityRRs,
		d.AdditionalRRs,
		d.rrecords(),
	)
}

func (d *DNSMessage) Summary() string {
	return fmt.Sprintf("DNS Message: %s %s %#04x", d.Flags.OPCodeDesc, d.Flags.QRDesc, d.TransactionID)
}

// Parse parses the given byte data into a DNSMessage struct.
func (d *DNSMessage) Parse(data []byte) error {
	if len(data) < headerSizeDNS {
		return fmt.Errorf("minimum header size for DNS is %d bytes, got %d bytes", headerSizeDNS, len(data))
	}
	d.TransactionID = binary.BigEndian.Uint16(data[0:2])
	d.Flags = newDNSFlags(binary.BigEndian.Uint16(data[2:4]))
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

func qrdesc(qr uint8) string {
	var qrdesc string
	switch qr {
	case 0:
		qrdesc = "query"
	case 1:
		qrdesc = "reply"
	}
	return qrdesc
}

// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5
func opcdesc(opcode uint8) string {
	var opcdesc string
	switch opcode {
	case 0:
		opcdesc = "Standard query"
	case 1:
		opcdesc = "Inverse query"
	case 2:
		opcdesc = "Server status request"
	case 4:
		opcdesc = "Notify"
	case 5:
		opcdesc = "Update"
	case 6:
		opcdesc = "Stateful operation"
	default:
		opcdesc = "Unknown"
	}
	return opcdesc
}

// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
func rcdesc(rcode uint8) string {
	var rcdesc string
	switch rcode {
	case 0:
		rcdesc = "No error"
	case 1:
		rcdesc = "Format error"
	case 2:
		rcdesc = "Server failed to complete the DNS request"
	case 3:
		rcdesc = "Domain name does not exist"
	case 4:
		rcdesc = "Function not implemented"
	case 5:
		rcdesc = "The server refused to answer for the query"
	case 6:
		rcdesc = "Name that should not exist, does exist"
	case 7:
		rcdesc = "RRset that should not exist, does exist"
	case 8:
		rcdesc = "Server not authoritative for the zone"
	case 9:
		rcdesc = "Server Not Authoritative for zone"
	case 10:
		rcdesc = "Name not contained in zone"
	case 11:
		rcdesc = "DSO-TYPE Not Implemented"
	case 16:
		rcdesc = "Bad OPT Version/TSIG Signature Failure"
	case 17:
		rcdesc = "Key not recognizede"
	case 18:
		rcdesc = "Signature out of time window"
	case 19:
		rcdesc = "Bad TKEY Mode"
	case 20:
		rcdesc = "Duplicate key name"
	case 21:
		rcdesc = "Algorithm not supported"
	case 22:
		rcdesc = "Bad Truncation"
	case 23:
		rcdesc = "Bad/missing Server Cookie"
	default:
		rcdesc = "Unknown"
	}
	return rcdesc
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
