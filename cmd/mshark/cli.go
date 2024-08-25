package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	ms "github.com/shadowy-pycoder/mshark"
)

const usagePrefix = `
                ______   __                            __       
               /      \ |  \                          |  \      
 ______ ____  |  $$$$$$\| $$____    ______    ______  | $$   __ 
|      \    \ | $$___\$$| $$    \  |      \  /      \ | $$  /  \
| $$$$$$\$$$$\ \$$    \ | $$$$$$$\  \$$$$$$\|  $$$$$$\| $$_/  $$
| $$ | $$ | $$ _\$$$$$$\| $$  | $$ /      $$| $$   \$$| $$   $$ 
| $$ | $$ | $$|  \__| $$| $$  | $$|  $$$$$$$| $$      | $$$$$$\ 
| $$ | $$ | $$ \$$    $$| $$  | $$ \$$    $$| $$      | $$  \$$\
 \$$  \$$  \$$  \$$$$$$  \$$   \$$  \$$$$$$$ \$$       \$$   \$$
                                                                                                                                                                                              
Packet Capture Tool by shadowy-pycoder 

GitHub: https://github.com/shadowy-pycoder/mshark

Usage: mshark [OPTIONS]
Options:
  -h    Show this help message and exit.
`

func displayInterfaces() error {
	w := new(tabwriter.Writer)
	w.Init(os.Stdout, 0, 0, 2, ' ', tabwriter.TabIndent)
	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("failed to get network interfaces: %v", err)
	}
	fmt.Fprintln(w, "Index\tName\tFlags")
	fmt.Fprintln(w, "0\tany\tUP")
	for _, iface := range ifaces {
		fmt.Fprintf(w, "%d\t%s\t%s\n", iface.Index, iface.Name, strings.ToUpper(iface.Flags.String()))
	}
	return w.Flush()
}

func root(args []string) error {
	conf := ms.Config{}

	flags := flag.NewFlagSet("mshark", flag.ExitOnError)
	flags.StringVar(&conf.Iface, "i", "any", "The name of the network interface. Example: eth0")
	flags.IntVar(&conf.Snaplen, "s", 0, "The maximum length of each packet snapshot. Defaults to 65535.")
	flags.BoolFunc("p", `Promiscuous mode. This setting is ignored for "any" interface. Defaults to false.`, func(flagValue string) error {
		conf.Promisc = true
		return nil
	})
	flags.DurationVar(&conf.Timeout, "t", 0, "The maximum duration of the packet capture process. Example: 5s")
	flags.IntVar(&conf.PacketCount, "c", 0, "The maximum number of packets to capture.")
	flags.StringVar(&conf.Expr, "e", "", `BPF filter expression. Example: "ip proto tcp"`)
	path := flags.String("f", "", "File path to write captured packet data to. Defaults to stdout.")
	flags.BoolFunc("pcap", "Create a PCAP file in the current working directory.", func(flagValue string) error {
		conf.Pcap = true
		return nil
	})
	flags.BoolFunc("D", "Display list of interfaces and exit.", func(flagValue string) error {
		if err := displayInterfaces(); err != nil {
			fmt.Fprintf(os.Stderr, "mshark: %v\n", err)
			os.Exit(2)
		}
		os.Exit(0)
		return nil
	})

	flags.Usage = func() {
		fmt.Print(usagePrefix)
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		return err
	}

	if *path != "" {
		f, err := os.OpenFile(filepath.FromSlash(*path), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("failed to open file: %v", err)
		}
		defer f.Close()
		conf.File = f
	}

	if err := ms.OpenLive(&conf); err != nil {
		return err
	}
	return nil
}
