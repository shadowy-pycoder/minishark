package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	ms "github.com/shadowy-pycoder/mshark"
	"github.com/shadowy-pycoder/mshark/mpcap"
	"github.com/shadowy-pycoder/mshark/mpcapng"
)

const app string = "mshark"

const usagePrefix string = `
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

var supportedFormats = []string{"stdout", "txt", "pcap", "pcapng"}

var (
	_ ms.PacketWriter = &mpcap.Writer{}
	_ ms.PacketWriter = &mpcapng.Writer{}
)

type ExtFlag []string

func (f *ExtFlag) MarshalText() ([]byte, error) {
	return nil, nil
}

func (f *ExtFlag) UnmarshalText(b []byte) error {
	exts := *f
	for _, ext := range strings.Split(string(b), ",") {
		if !slices.Contains(exts, ext) && slices.Contains(supportedFormats, ext) {
			exts = append(exts, ext)
		}
	}
	*f = exts
	return nil
}

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

func createFile(app, ext string) (*os.File, error) {
	path := fmt.Sprintf("./%s_%s.%s", app, time.Now().UTC().Format("20060102_150405"), ext)
	f, err := os.OpenFile(filepath.FromSlash(path), os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	return f, nil
}

func root(args []string) error {
	conf := ms.Config{}

	flags := flag.NewFlagSet(app, flag.ExitOnError)
	iface := flags.String("i", "any", "The name of the network interface. Example: eth0")
	snaplen := flags.Int("s", 0, "The maximum length of each packet snapshot. Defaults to 65535.")
	flags.BoolFunc("p", `Promiscuous mode. This setting is ignored for "any" interface. Defaults to false.`, func(flagValue string) error {
		conf.Promisc = true
		return nil
	})
	flags.DurationVar(&conf.Timeout, "t", 0, "The maximum duration of the packet capture process. Example: 5s")
	flags.IntVar(&conf.PacketCount, "c", 0, "The maximum number of packets to capture.")
	flags.StringVar(&conf.Expr, "e", "", `BPF filter expression. Example: "ip proto tcp".`)
	flags.BoolFunc("D", "Display list of interfaces and exit.", func(flagValue string) error {
		if err := displayInterfaces(); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", app, err)
			os.Exit(2)
		}
		os.Exit(0)
		return nil
	})
	var verbose bool
	flags.BoolFunc("v", "Display full packet info when capturing to stdout or txt.", func(flagValue string) error {
		verbose = true
		return nil
	})
	exts := ExtFlag([]string{})
	flags.TextVar(&exts, "f", &exts, "File extension(s) to write captured data. Supported formats: stdout, txt, pcap, pcapng")

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

	// creating writers and writing headers depending on a file extension
	var pw []ms.PacketWriter
	if len(exts) != 0 {
		for _, ext := range exts {
			switch ext {
			case "stdout":
				w := ms.NewWriter(os.Stdout, verbose)
				if err := w.WriteHeader(&conf); err != nil {
					return err
				}
				pw = append(pw, w)
			case "txt":
				f, err := createFile(app, ext)
				if err != nil {
					return err
				}
				defer f.Close()
				w := ms.NewWriter(f, verbose)
				if err := w.WriteHeader(&conf); err != nil {
					return err
				}
				pw = append(pw, w)
			case "pcap":
				f, err := createFile(app, ext)
				if err != nil {
					return err
				}
				defer f.Close()
				w := mpcap.NewWriter(f)
				if err := w.WriteHeader(conf.Snaplen); err != nil {
					return err
				}
				pw = append(pw, w)
			case "pcapng":
				f, err := createFile(app, ext)
				if err != nil {
					return err
				}
				defer f.Close()
				w := mpcapng.NewWriter(f)
				if err := w.WriteHeader(app, conf.Device, conf.Expr, conf.Snaplen); err != nil {
					return err
				}
				pw = append(pw, w)
			default:
				// unreachable
				return fmt.Errorf("unsupported file format: %s", ext)
			}
		}
	} else {
		w := ms.NewWriter(os.Stdout, verbose)
		if err := w.WriteHeader(&conf); err != nil {
			return err
		}
		pw = append(pw, w)
	}
	if err := ms.OpenLive(&conf, pw...); err != nil {
		return err
	}
	return nil
}
