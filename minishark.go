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

func OpenLive(iface string, snaplen int, promisc bool, timeout time.Duration, count int, expr string, path string) error {

	cfg := packet.Config{}

	// setting up filter
	if expr != "" {
		e := filter.NewExpression(expr)
		f := e.Compile()
		instructions, err := f.Compile()
		if err != nil {
			return fmt.Errorf("failed to compile filter into instructions: %v", err)
		}
		raw, err := bpf.Assemble(instructions)
		if err != nil {
			return fmt.Errorf("bpf assembly failed: %v", err)
		}
		cfg.Filter = raw
	}

	var (
		in  *net.Interface
		err error
	)
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
	c, err := packet.Listen(in, packet.Raw, unix.ETH_P_ALL, &cfg)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return fmt.Errorf("permission denied (try setting CAP_NET_RAW capability): %v", err)
		}
		return fmt.Errorf("failed to listen: %v", err)
	}

	// setting promisc mode
	if in.Name != "any" {
		if err = c.SetPromiscuous(promisc); err != nil {
			return fmt.Errorf("unable to set promiscuous mode: %v", err)
		}
	}

	// timeout
	if timeout > 0 {
		err = c.SetDeadline(time.Now().Add(timeout))
		if err != nil {
			return fmt.Errorf("unable to set timeout: %v", err)
		}
	}

	var (
		ether EthernetFrame
		ip    IPv4Packet
		ip6   IPv6Packet
		arp   ARPPacket
		tcp   TCPSegment
		udp   UDPSegment
		icmp  ICMPSegment
		icmp6 ICMPv6Segment
	)
	// snaplen
	if snaplen <= 0 {
		snaplen = 65535
	}
	b := make([]byte, snaplen)

	// file to write packets
	var f *os.File
	if path == "" {
		f = os.Stdout
	} else {
		f, err = os.OpenFile(filepath.FromSlash(path), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("failed to open file: %v", err)
		}
		defer f.Close()
	}

	// number of packets
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
		in.Name != "any" && promisc,
		timeout,
		count,
		expr,
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

		fmt.Fprintf(f, "- Packets: %d, Drops: %d, Freeze Queue Count: %d\n- Packets Captured: %d",
			stats.Packets, stats.Drops, stats.FreezeQueueCount, packets)
		// close Conn
		c.Close()
	}()
	for i := 0; infinity || i < count; i++ {
		n, _, err := c.ReadFrom(b)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return nil
			}
			return fmt.Errorf("failed to read Ethernet frame: %v", err)
		}

		if err := ether.Parse(b[:n]); err != nil {
			f.WriteString(err.Error() + "\n")
			continue
		}
		packets++
		fmt.Fprintf(f, "- Packet: %d Timestamp: %s\n", packets, time.Now().UTC().Format("2006-01-02T15:04:05-0700"))
		f.WriteString("==================================================================" + "\n")
		f.WriteString(ether.String() + "\n")
		switch ether.NextLayer() {
		case "IPv4":
			if err := ip.Parse(ether.Payload); err != nil {
				f.WriteString(err.Error() + "\n")
				continue
			}
			f.WriteString(ip.String() + "\n")
			switch ip.NextLayer() {
			case "TCP":
				if err := tcp.Parse(ip.Payload); err != nil {
					f.WriteString(err.Error() + "\n")
					continue
				}
				f.WriteString(tcp.String() + "\n")
			case "UDP":
				if err := udp.Parse(ip.Payload); err != nil {
					f.WriteString(err.Error() + "\n")
					continue
				}
				f.WriteString(udp.String() + "\n")
			case "ICMP":
				if err := icmp.Parse(ip.Payload); err != nil {
					f.WriteString(err.Error() + "\n")
					continue
				}
				f.WriteString(icmp.String() + "\n")
			}
		case "IPv6":
			if err := ip6.Parse(ether.Payload); err != nil {
				f.WriteString(err.Error() + "\n")
				continue
			}
			f.WriteString(ip6.String() + "\n")
			switch ip6.NextLayer() {
			case "TCP":
				if err := tcp.Parse(ip6.Payload); err != nil {
					f.WriteString(err.Error() + "\n")
					continue
				}
				f.WriteString(tcp.String() + "\n")
			case "UDP":
				if err := udp.Parse(ip6.Payload); err != nil {
					f.WriteString(err.Error() + "\n")
					continue
				}
				f.WriteString(udp.String() + "\n")
			case "ICMPv6":
				if err := icmp6.Parse(ip6.Payload); err != nil {
					f.WriteString(err.Error() + "\n")
					continue
				}
				f.WriteString(icmp6.String() + "\n")
			}
		case "ARP":
			if err := arp.Parse(ether.Payload); err != nil {
				f.WriteString(err.Error() + "\n")
				continue
			}
			f.WriteString(arp.String() + "\n")
		}
	}
	return nil
}
