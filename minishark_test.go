package minishark

import (
	"os"
	"testing"
)

func BenchmarkOpenLive(b *testing.B) {
	b.ResetTimer()
	if err := OpenLive("any", 1600, true, 0, b.N, "", os.DevNull); err != nil {
		b.Fatal(err)
	}
}
