package main

import (
	"flag"
	"fmt"

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

func root(args []string) error {
	conf := ms.Config{}

	flags := flag.NewFlagSet("mshark", flag.ExitOnError)
	flags.StringVar(&conf.Iface, "i", "any", "The name of the network interface. Example: eth0")
	flags.IntVar(&conf.Snaplen, "s", 0, "The maximum length of each packet snapshot. Defaults to 65535.")
	flags.BoolFunc("p", `Promiscuous mode. This setting is ignored for "any" interface.`, func(flagValue string) error {
		conf.Promisc = true
		return nil
	})
	flags.DurationVar(&conf.Timeout, "t", 0, "The maximum duration of the packet capture process. Example: 5s")
	flags.IntVar(&conf.PacketCount, "c", 0, "The maximum number of packets to capture.")
	flags.StringVar(&conf.Expr, "e", "", `BPF filter expression. Example: "ip proto tcp"`)
	flags.StringVar(&conf.Path, "f", "", "File path to write captured packet data to. Example: ./captured.txt")
	flags.BoolFunc("pcap", "Whether to create PCAP file.", func(flagValue string) error {
		conf.Pcap = true
		return nil
	})
	flags.StringVar(&conf.PcapPath, "path", "", "Path to a PCAP file. Example: ./captured.pcap")

	flags.Usage = func() {
		fmt.Print(usagePrefix)
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		return err
	}

	if err := ms.OpenLive(&conf); err != nil {
		return err
	}
	return nil
}
