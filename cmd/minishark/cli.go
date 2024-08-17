package main

import (
	"fmt"
	"time"

	ms "github.com/shadowy-pycoder/minishark"
)

func root() {
	if err := ms.OpenLive("any", 1600, true, 5*time.Second, 10000, "ip src not host 127.0.0.1", ""); err != nil {
		fmt.Println(err)
	}
}
