package layers

import (
	"fmt"
	"unsafe"
)

const maxLenSummary = 100

var LayerMap = map[string]Layer{
	"ETH":    &EthernetFrame{},
	"IPv4":   &IPv4Packet{},
	"IPv6":   &IPv6Packet{},
	"ARP":    &ARPPacket{},
	"TCP":    &TCPSegment{},
	"UDP":    &UDPSegment{},
	"ICMP":   &ICMPSegment{},
	"ICMPv6": &ICMPv6Segment{},
	"DNS":    &DNSMessage{},
	"FTP":    &FTPMessage{},
	"HTTP":   &HTTPMessage{},
	"SNMP":   &SNMPMessage{},
	"SSH":    &SSHMessage{},
	"TLS":    &TLSMessage{},
}

var (
	bspace   = []byte(" ")
	dash     = []byte("- ")
	lfd      = []byte("\n- ")
	lf       = []byte("\n")
	crlf     = []byte("\r\n")
	dcrlf    = []byte("\r\n\r\n")
	proto    = []byte("HTTP/1.1")
	ellipsis = []byte("...")
	contdata = []byte("Continuation data")
)

type Layer interface {
	fmt.Stringer
	Parse(data []byte) error
	NextLayer() (layer string, payload []byte)
	Summary() string
}

func nextAppLayer(src, dst uint16) string {
	var layer string
	switch {
	case src == 20 || dst == 20 || src == 21 || dst == 21:
		layer = "FTP"
	case src == 22 || dst == 22:
		layer = "SSH"
	case src == 53 || dst == 53:
		layer = "DNS"
	case src == 80 || dst == 80:
		layer = "HTTP"
	case src == 161 || dst == 161 || src == 162 || dst == 162:
		layer = "SNMP"
	case src == 443 || dst == 443:
		layer = "TLS"
	default:
		layer = ""
	}
	return layer
}

func bytesToStr(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}

func joinBytes(bs ...[]byte) []byte {
	n := 0
	for _, v := range bs {
		n += len(v)
	}
	b, i := make([]byte, n), 0
	for _, v := range bs {
		i += copy(b[i:], v)
	}
	return b
}
