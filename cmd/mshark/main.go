package main

import (
	"fmt"
	"os"
)

func main() {
	if err := root(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "mshark: %v\n", err)
		os.Exit(2)
	}
}
