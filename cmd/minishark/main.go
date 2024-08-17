package main

import (
	"fmt"
	"time"

	ms "github.com/shadowy-pycoder/minishark"
)

func main() {
	if err := ms.OpenLive("any", 1600, true, 60*time.Second, 100, "ip proto udp"); err != nil {
		fmt.Println(err)
	}
}
