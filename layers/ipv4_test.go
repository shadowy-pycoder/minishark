package layers

import (
	"fmt"
	"io"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func BenchmarkParseIPv4(b *testing.B) {
	packet, close := testPacketBench(b, "ipv4")
	defer close()
	b.ResetTimer()
	ip := &IPv4Packet{}
	for i := 0; i < b.N; i++ {
		_ = ip.Parse(packet)
		fmt.Fprint(io.Discard, ip.String())
	}
}

func TestParseIPv4(t *testing.T) {
	expected := &IPv4Packet{
		Version:        4,
		IHL:            5,
		DSCP:           0,
		DSCPDesc:       "Standard (DF)",
		ECN:            0,
		TotalLength:    52,
		Identification: 47117,
		Flags:          &IPv4Flags{Reserved: 0, MF: 0, DF: 1},
		FragmentOffset: 0,
		TTL:            64,
		Protocol:       6,
		ProtocolDesc:   "TCP",
		HeaderChecksum: 33972,
		SrcIP:          netip.AddrFrom4([4]byte{0x7F, 0x00, 0x00, 0x01}),
		DstIP:          netip.AddrFrom4([4]byte{0x7F, 0x00, 0x00, 0x02}),
		payload:        []byte{},
	}
	ip := &IPv4Packet{}
	packet, close := testPacket(t, "ipv4")
	defer close()
	if err := ip.Parse(packet); err != nil {
		t.Fatal(err)
	}
	require.Equal(t, expected, ip)
}
