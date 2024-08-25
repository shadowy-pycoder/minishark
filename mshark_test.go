package mshark

import (
	"io"
	"testing"
)

func BenchmarkOpenLive(b *testing.B) {
	b.ResetTimer()
	conf := Config{
		Iface:       "any",
		Snaplen:     1600,
		Promisc:     true,
		PacketCount: b.N,
		File:        io.Discard,
	}
	if err := OpenLive(&conf); err != nil {
		b.Fatal(err)
	}
}
