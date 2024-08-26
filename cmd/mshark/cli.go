package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	ms "github.com/shadowy-pycoder/mshark"
	"github.com/shadowy-pycoder/mshark/mpcap"
	"github.com/shadowy-pycoder/mshark/mpcapng"
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

func createFile(ext string) (*os.File, error) {
	path := fmt.Sprintf("./mshark_%s.%s", time.Now().UTC().Format("20060102_150405"), ext)
	f, err := os.OpenFile(filepath.FromSlash(path), os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	return f, nil
}

func root(args []string) error {
	conf := ms.Config{}

	flags := flag.NewFlagSet("mshark", flag.ExitOnError)
	iface := flags.String("i", "any", "The name of the network interface. Example: eth0")
	snaplen := flags.Int("s", 0, "The maximum length of each packet snapshot. Defaults to 65535.")
	flags.BoolFunc("p", `Promiscuous mode. This setting is ignored for "any" interface. Defaults to false.`, func(flagValue string) error {
		conf.Promisc = true
		return nil
	})
	flags.DurationVar(&conf.Timeout, "t", 0, "The maximum duration of the packet capture process. Example: 5s")
	flags.IntVar(&conf.PacketCount, "c", 0, "The maximum number of packets to capture.")
	flags.StringVar(&conf.Expr, "e", "", `BPF filter expression. Example: "ip proto tcp"`)
	ext := flags.String("f", "", "File extension to write captured packet data to. Supported values: txt, pcap, pcapng")
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

	// getting network interface from the provided name
	in, err := ms.InterfaceByName(*iface)
	if err != nil {
		return err
	}
	conf.Device = in

	// checking snaplen
	if *snaplen <= 0 || *snaplen > 65535 {
		*snaplen = 65535
	}
	conf.Snaplen = *snaplen

	// creating writers depending on a file extension
	var pw ms.PacketWriter
	if *ext != "" {
		switch *ext {
		case "txt":
			f, err := createFile(*ext)
			if err != nil {
				return err
			}
			defer f.Close()
			pw = ms.NewWriter(f)
		case "pcap":
			f, err := createFile(*ext)
			if err != nil {
				return err
			}
			defer f.Close()
			pw = mpcap.NewWriter(f)
		case "pcapng":
			f, err := createFile(*ext)
			if err != nil {
				return err
			}
			defer f.Close()
			pw = mpcapng.NewWriter(f)
		default:
			return fmt.Errorf("unsupported file format: %s", *ext)
		}
	} else {
		pw = ms.NewWriter(os.Stdout)
	}

	// writing headers
	switch t := pw.(type) {
	case *ms.Writer:
		if err := t.WriteHeader(&conf); err != nil {
			return err
		}
	case *mpcap.Writer:
		if err := t.WriteHeader(conf.Snaplen); err != nil {
			return err
		}
	case *mpcapng.Writer:
		if err := t.WriteHeader("mshark", conf.Device, conf.Expr, conf.Snaplen); err != nil {
			return err
		}
	}
	if err := ms.OpenLive(&conf, pw); err != nil {
		return err
	}
	return nil
}
