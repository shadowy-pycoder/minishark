package mshark

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/mdlayher/packet"
	"github.com/packetcap/go-pcap/filter"
	"github.com/shadowy-pycoder/mshark/mpcap"
	"github.com/shadowy-pycoder/mshark/mpcapng"
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
	Snaplen     int           // The maximum length of each packet snapshot.
	Promisc     bool          // Promiscuous mode. This setting is ignored for "any" interface.
	Timeout     time.Duration // The maximum duration of the packet capture process.
	PacketCount int           // The maximum number of packets to capture.
	Expr        string        // BPF filter expression.
	File        io.Writer     // File to write captured packet data to.
	Pcap        bool          // Create a PCAP file in the current working directory.
	PcapNG      bool          // Create a PCAPNG file in the current working directory.
}

type Writer struct {
	w         io.Writer
	layers    layers
	packetNum uint64
}

func NewWriter(w io.Writer) *Writer {
	if w == nil {
		w = os.Stdout
	}
	return &Writer{w: w}
}

func (mw *Writer) WritePacket(timestamp time.Time, data []byte) error {
	mw.packetNum++
	fmt.Fprintf(mw.w, "- Packet: %d Timestamp: %s\n", mw.packetNum, timestamp.Format("2006-01-02T15:04:05-0700"))
	fmt.Fprintln(mw.w, "==================================================================")
	if err := mw.layers.ether.Parse(data); err != nil {
		return err
	}
	fmt.Fprintln(mw.w, mw.layers.ether.String())
	switch mw.layers.ether.NextLayer() {
	case "IPv4":
		if err := mw.layers.ip.Parse(mw.layers.ether.Payload); err != nil {
			return err
		}
		fmt.Fprintln(mw.w, mw.layers.ip.String())
		switch mw.layers.ip.NextLayer() {
		case "TCP":
			if err := mw.layers.tcp.Parse(mw.layers.ip.Payload); err != nil {
				return err
			}
			fmt.Fprintln(mw.w, mw.layers.tcp.String())
		case "UDP":
			if err := mw.layers.udp.Parse(mw.layers.ip.Payload); err != nil {
				return err
			}
			fmt.Fprintln(mw.w, mw.layers.udp.String())
		case "ICMP":
			if err := mw.layers.icmp.Parse(mw.layers.ip.Payload); err != nil {
				return err
			}
			fmt.Fprintln(mw.w, mw.layers.icmp.String())
		}
	case "IPv6":
		if err := mw.layers.ip6.Parse(mw.layers.ether.Payload); err != nil {
			return err
		}
		fmt.Fprintln(mw.w, mw.layers.ip6.String())
		switch mw.layers.ip6.NextLayer() {
		case "TCP":
			if err := mw.layers.tcp.Parse(mw.layers.ip6.Payload); err != nil {
				return err
			}
			fmt.Fprintln(mw.w, mw.layers.tcp.String())
		case "UDP":
			if err := mw.layers.udp.Parse(mw.layers.ip6.Payload); err != nil {
				return err
			}
			fmt.Fprintln(mw.w, mw.layers.udp.String())
		case "ICMPv6":
			if err := mw.layers.icmp6.Parse(mw.layers.ip6.Payload); err != nil {
				return err
			}
			fmt.Fprintln(mw.w, mw.layers.icmp6.String())
		}
	case "ARP":
		if err := mw.layers.arp.Parse(mw.layers.ether.Payload); err != nil {
			return err
		}
		fmt.Fprintln(mw.w, mw.layers.arp.String())
	}
	return nil
}

func (mw *Writer) WriteHeader(c *Config, in *net.Interface, snaplen int) error {
	_, err := fmt.Fprintf(mw.w, `- Interface: %s
- Snapshot Length: %d
- Promiscuous Mode: %v
- Timeout: %s
- Number of Packets: %d
- BPF Filter: %q

`,
		in.Name,
		snaplen,
		in.Name != "any" && c.Promisc,
		c.Timeout,
		c.PacketCount,
		c.Expr,
	)
	return err
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
	if snaplen <= 0 || snaplen > 65535 {
		snaplen = 65535
	}
	b := make([]byte, snaplen)

	// file to write packets
	f := NewWriter(conf.File)
	if err = f.WriteHeader(conf, in, snaplen); err != nil {
		return err
	}
	// number of packets
	count := conf.PacketCount
	if count < 0 {
		count = 0
	}
	infinity := count == 0

	defer func() {
		stats, err := c.Stats()
		if err != nil {
			fmt.Printf("failed to fetch stats: %v", err)
		}
		// Received some data, assume some Stats were populated.
		if stats.Packets == 0 {
			fmt.Println("stats indicated 0 received packets")
		}

		fmt.Fprintf(f.w, "- Packets: %d, Drops: %d, Freeze Queue Count: %d\n- Packets Captured: %d\n",
			stats.Packets, stats.Drops, stats.FreezeQueueCount, f.packetNum)
		// close Conn
		c.Close()
	}()

	// pcap file to write packets
	var pcap *mpcap.Writer
	if conf.Pcap {
		path := fmt.Sprintf("./mshark_%s.pcap", time.Now().UTC().Format("20060102_150405"))
		fpcap, err := os.OpenFile(filepath.FromSlash(path), os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("failed to open file: %v", err)
		}
		defer fpcap.Close()
		pcap = mpcap.NewWriter(fpcap)
		if err = pcap.WriteHeader(snaplen); err != nil {
			return err
		}
	}

	// pcapng file to write packets
	var pcapng *mpcapng.Writer
	if conf.PcapNG {
		path := fmt.Sprintf("./mshark_%s.pcapng", time.Now().UTC().Format("20060102_150405"))
		fpcapng, err := os.OpenFile(filepath.FromSlash(path), os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("failed to open file: %v", err)
		}
		defer fpcapng.Close()
		pcapng = mpcapng.NewWriter(fpcapng)
		if err = pcapng.WriteHeader("mshark", in, conf.Expr, conf.Snaplen); err != nil {
			return err
		}
	}

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

		if conf.PcapNG {
			if err = pcapng.WritePacket(timestamp, data); err != nil {
				return err
			}
		}

		if err = f.WritePacket(timestamp, data); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}
	return nil
}
