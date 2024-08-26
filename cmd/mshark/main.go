package main

import (
	"fmt"
	"os"
)

func main() {
	if err := root(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", app, err)
		os.Exit(2)
	}
}
