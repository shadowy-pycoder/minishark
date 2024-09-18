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
