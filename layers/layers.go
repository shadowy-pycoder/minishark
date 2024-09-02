package layers

import (
	"fmt"
	"unsafe"
)

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

type Layer interface {
	fmt.Stringer
	Parse(data []byte) error
	NextLayer() (name string, payload []byte)
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
