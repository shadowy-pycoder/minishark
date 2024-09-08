package layers

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

const messageSizeSSH = 6

type Message struct {
	PacketLength     uint32
	PaddingLength    uint8
	MesssageType     uint8
	MesssageTypeDesc string
	Payload          []byte
}

func (m *Message) String() string {
	if m.PacketLength == 0 {
		return fmt.Sprintf(`- Payload: %d bytes`, len(m.Payload))
	}
	return fmt.Sprintf(` - Packet Length: %d
 - Padding Length: %d
 - Message Type: %s (%d)
 - Payload: %d bytes`,
		m.PacketLength,
		m.PaddingLength,
		m.MesssageTypeDesc,
		m.MesssageType,
		len(m.Payload))
}

type SSHMessage struct {
	Protocol string
	Messages []*Message
}

func (s *SSHMessage) String() string {
	return fmt.Sprintf(`%s
%s
`, s.Summary(), s.printMessages())
}

func (s *SSHMessage) Summary() string {
	var sb strings.Builder
	sb.WriteString("SSH Message: ")
	if s.Protocol != "" {
		sb.WriteString(s.Protocol)
		return sb.String()
	}
	if len(s.Messages) == 1 && s.Messages[0].PacketLength == 0 {
		sb.WriteString(fmt.Sprintf("Encrypted or partial data Len: %d", len(s.Messages[0].Payload)))
		return sb.String()
	}
	for _, message := range s.Messages {
		if message.PacketLength != 0 {
			sb.WriteString(fmt.Sprintf("%s (%d) Len: %d ",
				message.MesssageTypeDesc,
				message.MesssageType,
				message.PacketLength))
		}
		if sb.Len() > maxLenSummary {
			return sb.String()[:maxLenSummary] + string(ellipsis)
		}
	}
	return sb.String()
}

func (s *SSHMessage) printMessages() string {
	var sb strings.Builder

	for _, message := range s.Messages {
		if message.MesssageTypeDesc == "" {
			sb.WriteString(fmt.Sprintf("%s\n", message))
		} else {
			sb.WriteString(fmt.Sprintf("- %s:\n%s\n", message.MesssageTypeDesc, message))
		}
	}
	return sb.String()
}

func (s *SSHMessage) Parse(data []byte) error {
	if len(data) < messageSizeSSH {
		return fmt.Errorf("minimum message size for SSH is %d bytes, got %d bytes", messageSizeSSH, len(data))
	}
	s.Protocol = ""
	s.Messages = nil
	if bytes.HasSuffix(data, crlf) {
		s.Protocol = bytesToStr(bytes.TrimSuffix(data, crlf))
		return nil
	}
	s.Messages = make([]*Message, 0, 3)
	for len(data) > 0 {
		m := &Message{}
		s.Messages = append(s.Messages, m)
		plen := binary.BigEndian.Uint32(data[0:4])
		if plen > 0xffff {
			m.Payload = data
			break
		}
		m.MesssageType = data[5]
		if m.MesssageTypeDesc = mtypedesc(m.MesssageType); m.MesssageTypeDesc == "Unknown" {
			m.Payload = data
			break
		}
		m.PacketLength = plen
		m.PaddingLength = data[4]
		offset := int(messageSizeSSH + m.PacketLength - 2)
		if offset <= len(data) {
			m.Payload = data[messageSizeSSH:offset]
			data = data[offset:]
		} else {
			m.Payload = data[messageSizeSSH:]
			break
		}
	}
	return nil
}

func (s *SSHMessage) NextLayer() (string, []byte) {
	return "", nil
}

// https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml
func mtypedesc(mtype uint8) string {
	var mtypedesc string
	switch mtype {
	case 20:
		mtypedesc = "Key Exchange Init"
	case 21:
		mtypedesc = "New Keys"
	case 30:
		mtypedesc = "Elliptic Curve Diffie-Hellman Key Exchange Init"
	case 31:
		mtypedesc = "Elliptic Curve Diffie-Hellman Key Exchange Reply"
	default:
		mtypedesc = "Unknown"
	}
	return mtypedesc
}
