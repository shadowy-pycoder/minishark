package minishark

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/mdlayher/packet"
	"github.com/packetcap/go-pcap/filter"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

type layers struct {
	ether EthernetFrame
	ip    IPv4Packet
	ip6   IPv6Packet
	arp   ARPPacket
	tcp   TCPSegment
	udp   UDPSegment
	icmp  ICMPSegment
	icmp6 ICMPv6Segment
}

type Config struct {
	Iface       string        // The name of the network interface ("any" means listen on all interfaces).
	Snaplen     int32         // The maximum length of each packet snapshot. Defaults to 65535.
	Promisc     bool          // Promiscuous mode. This setting is ignored for "any" interface.
	Timeout     time.Duration // The maximum duration of the packet capture process.
	PacketCount int           // The maximum number of packets to capture.
	Expr        string        // BPF filter expression.
	Path        string        // File path to write captured packet data to.
	Pcap        bool          // Whether to create PCAP file.
	PcapPath    string        // Path to a PCAP file. Defaults to "minishark.pcap" in the current working directory.
}

func OpenLive(conf *Config) error {

	packetcfg := packet.Config{}

	// setting up filter
	if conf.Expr != "" {
		e := filter.NewExpression(conf.Expr)
		f := e.Compile()
		instructions, err := f.Compile()
		if err != nil {
			return fmt.Errorf("failed to compile filter into instructions: %v", err)
		}
		raw, err := bpf.Assemble(instructions)
		if err != nil {
			return fmt.Errorf("bpf assembly failed: %v", err)
		}
		packetcfg.Filter = raw
	}

	var (
		in  *net.Interface
		err error
	)
	iface := conf.Iface
	if iface == "any" {
		in = &net.Interface{Index: 0, Name: "any"}
	} else {
		in, err = net.InterfaceByName(iface)
		if err != nil {
			return fmt.Errorf("unknown interface %s: %v", iface, err)
		}
		ok := true &&
			// Look for an Ethernet interface.
			len(in.HardwareAddr) == 6 &&
			// Look for up, multicast, broadcast.
			in.Flags&(net.FlagUp|net.FlagMulticast|net.FlagBroadcast) != 0
		if !ok {
			return fmt.Errorf("interface %s is not up", iface)
		}
	}

	// opening connection
	c, err := packet.Listen(in, packet.Raw, unix.ETH_P_ALL, &packetcfg)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return fmt.Errorf("permission denied (try setting CAP_NET_RAW capability): %v", err)
		}
		return fmt.Errorf("failed to listen: %v", err)
	}

	// setting promisc mode
	if in.Name != "any" {
		if err = c.SetPromiscuous(conf.Promisc); err != nil {
			return fmt.Errorf("unable to set promiscuous mode: %v", err)
		}
	}

	// timeout
	if conf.Timeout > 0 {
		if err = c.SetDeadline(time.Now().Add(conf.Timeout)); err != nil {
			return fmt.Errorf("unable to set timeout: %v", err)
		}
	}
	// snaplen
	snaplen := conf.Snaplen
	if snaplen <= 0 {
		snaplen = 65535
	}
	b := make([]byte, snaplen)

	// file to write packets
	var f *os.File
	if conf.Path == "" {
		f = os.Stdout
	} else {
		f, err = os.OpenFile(filepath.FromSlash(conf.Path), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("failed to open file: %v", err)
		}
		defer f.Close()
	}

	// number of packets
	count := conf.PacketCount
	if count < 0 {
		count = 0
	}
	infinity := count == 0

	fmt.Fprintf(f, `- Interface: %s
- Snapshot Length: %d
- Promiscuous Mode: %v
- Timeout: %s
- Number of Packets: %d
- BPF Filter: %q

`,
		in.Name,
		snaplen,
		in.Name != "any" && conf.Promisc,
		conf.Timeout,
		count,
		conf.Expr,
	)
	var packets uint64
	defer func() {
		stats, err := c.Stats()
		if err != nil {
			fmt.Printf("failed to fetch stats: %v", err)
		}
		// Received some data, assume some Stats were populated.
		if stats.Packets == 0 {
			fmt.Println("stats indicated 0 received packets")
		}

		fmt.Fprintf(f, "- Packets: %d, Drops: %d, Freeze Queue Count: %d\n- Packets Captured: %d\n",
			stats.Packets, stats.Drops, stats.FreezeQueueCount, packets)
		// close Conn
		c.Close()
	}()

	// pcap file to write packets
	var pcap *pcapWriter
	if conf.Pcap {
		if conf.PcapPath == "" {
			conf.PcapPath = "./minishark.pcap"
		}
		fpcap, err := os.OpenFile(filepath.FromSlash(conf.PcapPath), os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("failed to open file: %v", err)
		}
		defer fpcap.Close()
		pcap = NewPcapWriter(fpcap)
		if err = pcap.WriteGlobalHeader(snaplen); err != nil {
			return err
		}
	}

	layers := layers{}
	for i := 0; infinity || i < count; i++ {
		n, _, err := c.ReadFrom(b)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return nil
			}
			return fmt.Errorf("failed to read Ethernet frame: %v", err)
		}

		timestamp := time.Now().UTC()
		data := b[:n]

		if conf.Pcap {
			if err = pcap.WritePacket(timestamp, data); err != nil {
				return err
			}
		}

		packets++
		if err = parsePacket(f, data, packets, timestamp, &layers); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}
	return nil
}

func parsePacket(f *os.File, data []byte, packetNum uint64, timestamp time.Time, layers *layers) error {

	fmt.Fprintf(f, "- Packet: %d Timestamp: %s\n", packetNum, timestamp.Format("2006-01-02T15:04:05-0700"))
	f.WriteString("==================================================================" + "\n")
	if err := layers.ether.Parse(data); err != nil {
		return err
	}
	f.WriteString(layers.ether.String() + "\n")
	switch layers.ether.NextLayer() {
	case "IPv4":
		if err := layers.ip.Parse(layers.ether.Payload); err != nil {
			return err
		}
		f.WriteString(layers.ip.String() + "\n")
		switch layers.ip.NextLayer() {
		case "TCP":
			if err := layers.tcp.Parse(layers.ip.Payload); err != nil {
				return err
			}
			f.WriteString(layers.tcp.String() + "\n")
		case "UDP":
			if err := layers.udp.Parse(layers.ip.Payload); err != nil {
				return err
			}
			f.WriteString(layers.udp.String() + "\n")
		case "ICMP":
			if err := layers.icmp.Parse(layers.ip.Payload); err != nil {
				return err
			}
			f.WriteString(layers.icmp.String() + "\n")
		}
	case "IPv6":
		if err := layers.ip6.Parse(layers.ether.Payload); err != nil {
			return err
		}
		f.WriteString(layers.ip6.String() + "\n")
		switch layers.ip6.NextLayer() {
		case "TCP":
			if err := layers.tcp.Parse(layers.ip6.Payload); err != nil {
				return err
			}
			f.WriteString(layers.tcp.String() + "\n")
		case "UDP":
			if err := layers.udp.Parse(layers.ip6.Payload); err != nil {
				return err
			}
			f.WriteString(layers.udp.String() + "\n")
		case "ICMPv6":
			if err := layers.icmp6.Parse(layers.ip6.Payload); err != nil {
				return err
			}
			f.WriteString(layers.icmp6.String() + "\n")
		}
	case "ARP":
		if err := layers.arp.Parse(layers.ether.Payload); err != nil {
			return err
		}
		f.WriteString(layers.arp.String() + "\n")
	}
	return nil
}
