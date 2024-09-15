package layers

import (
	"encoding/binary"
	"fmt"
	"strings"
)

const headerSizeTLS = 5

type Record struct {
	ContentType     uint8
	ContentTypeDesc string
	Version         uint16
	VersionDesc     string
	Length          uint16
	data            []byte
}

func (r *Record) String() string {
	return fmt.Sprintf(` - Content Type: %s (%d)
 - Version: %s (%#04x)
 - Length: %d`,
		r.ContentTypeDesc,
		r.ContentType,
		r.VersionDesc,
		r.Version,
		r.Length)
}

// port 443
// https://tls12.xargs.org/#client-hello/annotated
// https://tls13.xargs.org/#client-hello/annotated
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-5
type TLSMessage struct {
	Records []*Record
	Data    []byte
}

func (t *TLSMessage) String() string {
	return fmt.Sprintf(`%s
%s- Data: %d bytes
`, t.Summary(), t.printRecords(), len(t.Data))
}

func (t *TLSMessage) Summary() string {
	var sb strings.Builder
	sb.WriteString("TLS Message: ")
	if len(t.Records) == 0 {
		sb.WriteString(fmt.Sprintf("Ignored unknown record Len: %d", len(t.Data)))
	} else {
		for i, rec := range t.Records {
			if i > 0 {
				sb.WriteString(fmt.Sprintf("%s (%d) Len: %d ", rec.ContentTypeDesc, rec.ContentType, rec.Length))
				continue
			}
			sb.WriteString(fmt.Sprintf("%s (%#04x) ", rec.VersionDesc, rec.Version))
			if rec.ContentType == 22 {
				hstd := hstypedesc(rec.data[0])
				sb.WriteString(fmt.Sprintf("%s ", hstd))
			}
			sb.WriteString(fmt.Sprintf("%s (%d) Len: %d ",
				rec.ContentTypeDesc,
				rec.ContentType,
				rec.Length))
			if sb.Len() > maxLenSummary {
				return sb.String()[:maxLenSummary] + string(ellipsis)
			}
		}
	}
	return sb.String()
}

func (t *TLSMessage) printRecords() string {
	var sb strings.Builder

	for _, rec := range t.Records {
		sb.WriteString(fmt.Sprintf("- %s:\n%s\n", rec.ContentTypeDesc, rec))
	}
	return sb.String()
}

func (t *TLSMessage) Parse(data []byte) error {
	if len(data) < headerSizeTLS {
		return fmt.Errorf("minimum header size for TLS is %d bytes, got %d bytes", headerSizeTLS, len(data))
	}
	t.Records = make([]*Record, 0, 5)
	for len(data) > 0 {
		ctype := data[0]
		ctdesc := ctdesc(ctype)
		if ctdesc == "Unknown" {
			break
		}
		ver := binary.BigEndian.Uint16(data[1:3])
		verdesc := verdesc(ver)
		if verdesc == "Unknown" {
			break
		}
		rlen := binary.BigEndian.Uint16(data[3:headerSizeTLS])
		if headerSizeTLS+rlen > uint16(len(data)) {
			break
		}
		r := &Record{
			ContentType:     ctype,
			ContentTypeDesc: ctdesc,
			Version:         ver,
			VersionDesc:     verdesc,
			Length:          rlen,
			data:            data[headerSizeTLS : headerSizeTLS+rlen],
		}
		t.Records = append(t.Records, r)
		data = data[headerSizeTLS+rlen:]
	}
	t.Data = data
	return nil
}

func (t *TLSMessage) NextLayer() (layer string, payload []byte) { return }

func ctdesc(ct uint8) string {
	// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-5
	var ctdesc string
	switch ct {
	case 20:
		ctdesc = "Change Cipher Spec"
	case 21:
		ctdesc = "Alert"
	case 22:
		ctdesc = "Handshake"
	case 23:
		ctdesc = "Application Data"
	case 24:
		ctdesc = "Heartbeat"
	case 25:
		ctdesc = "tls12_cid"
	case 26:
		ctdesc = "ACK"
	default:
		ctdesc = "Unknown"
	}
	return ctdesc
}

func verdesc(ver uint16) string {
	var verdesc string
	switch ver {
	case 0x0200:
		verdesc = "SSL 2.0"
	case 0x0300:
		verdesc = "SSL 3.0"
	case 0x0301:
		verdesc = "TLS 1.0"
	case 0x0302:
		verdesc = "TLS 1.1"
	case 0x0303:
		verdesc = "TLS 1.2"
	case 0x0304:
		verdesc = "TLS 1.3"
	default:
		verdesc = "Unknown"
	}
	return verdesc
}

func hstypedesc(hstype uint8) string {
	// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-7
	var hstypedesc string
	switch hstype {
	case 0:
		hstypedesc = "Hello request"
	case 1:
		hstypedesc = "Client hello"
	case 2:
		hstypedesc = "Server hello"
	case 3:
		hstypedesc = "Hello verify request"
	case 4:
		hstypedesc = "New session ticket"
	case 5:
		hstypedesc = "End of early data"
	case 6:
		hstypedesc = "Hello retry request"
	case 8:
		hstypedesc = "Encrypted extensions"
	case 9:
		hstypedesc = "Request connection id"
	case 10:
		hstypedesc = "New connection id"
	case 11:
		hstypedesc = "Certificate"
	case 12:
		hstypedesc = "Server key exchange"
	case 13:
		hstypedesc = "Certificate request"
	case 14:
		hstypedesc = "Server hello done"
	case 15:
		hstypedesc = "Certificate verify"
	case 16:
		hstypedesc = "Client key exchange"
	case 17:
		hstypedesc = "Client certificate request"
	case 20:
		hstypedesc = "Finished"
	case 21:
		hstypedesc = "Certificate url"
	case 22:
		hstypedesc = "Certificate status"
	case 23:
		hstypedesc = "Supplemental data"
	case 24:
		hstypedesc = "Key update"
	case 25:
		hstypedesc = "Compressed certificate"
	case 26:
		hstypedesc = "EKT key"
	default:
		hstypedesc = "Unknown"
	}
	return hstypedesc
}
