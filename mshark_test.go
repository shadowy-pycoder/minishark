package mshark

import (
	"io"
	"testing"
)

func BenchmarkOpenLive(b *testing.B) {
	b.ResetTimer()
	in, err := InterfaceByName("any")
	if err != nil {
		b.Fatal(err)
	}
	conf := Config{
		Device:      in,
		Snaplen:     1600,
		PacketCount: b.N,
	}
	pw := NewWriter(io.Discard)
	if err := OpenLive(&conf, pw); err != nil {
		b.Fatal(err)
	}
}
