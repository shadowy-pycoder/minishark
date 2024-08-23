package main

import (
	"fmt"
	"time"

	ms "github.com/shadowy-pycoder/mshark"
)

func root() {
	conf := ms.Config{
		Iface:       "any",
		Snaplen:     1600,
		Promisc:     true,
		Timeout:     5 * time.Second,
		PacketCount: 10000,
		Expr:        "ip src not host 127.0.0.1",
	}
	if err := ms.OpenLive(&conf); err != nil {
		fmt.Println(err)
	}
}
