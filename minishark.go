package minishark

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"github.com/mdlayher/packet"
	"github.com/mdlayher/socket"
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

	var in *net.Interface
	var err error
	if iface == "any" {
		in = &net.Interface{Index: 0, Name: "any"}
	} else {
		in, err = net.InterfaceByName(iface)
		if err != nil {
			return fmt.Errorf("unknown interface %s: %v", iface, err)
		}
		// check the interface is up
		if in.Flags&net.FlagUp != net.FlagUp {
			return fmt.Errorf("interface %s is not up", iface)
		}
	}
	fmt.Printf("capturing from interface %s\n", in.Name)

	// openning connection
	c, err := packet.Listen(in, packet.Raw, unix.ETH_P_ALL, &cfg)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return fmt.Errorf("skipping, permission denied (try setting CAP_NET_RAW capability): %v", err)
		}
		return fmt.Errorf("failed to listen: %v", err)
	}

	// setting promisc mode
	if in.Name == "any" {
		ifis, err := net.Interfaces()
		if err != nil {
			return fmt.Errorf("failed to get network interfaces: %v", err)
		}
		if len(ifis) == 0 {
			return fmt.Errorf("no network interfaces found")
		}
		// getting access to unexported socket connection
		sock := *(**socket.Conn)(unsafe.Pointer(c))
		for _, ifi := range ifis {

			// true is used to line up other checks.
			ok := true &&
				// Look for an Ethernet interface.
				len(ifi.HardwareAddr) == 6 &&
				// Look for up, multicast, broadcast.
				ifi.Flags&(net.FlagUp|net.FlagMulticast|net.FlagBroadcast) != 0

			if ok {
				mreq := unix.PacketMreq{
					Ifindex: int32(ifi.Index),
					Type:    unix.PACKET_MR_PROMISC,
				}
				membership := unix.PACKET_DROP_MEMBERSHIP
				if promisc {
					membership = unix.PACKET_ADD_MEMBERSHIP
				}
				// does this really set promisc mode on all devices?
				err = sock.SetsockoptPacketMreq(unix.SOL_PACKET, membership, &mreq)
				if err != nil {
					return fmt.Errorf("unable to set promiscuous mode: %v", err)
				}
			}
		}
	} else {
		err = c.SetPromiscuous(promisc)
		if err != nil {
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
	defer func() {
		stats, err := c.Stats()
		if err != nil {
			log.Printf("failed to fetch stats: %v", err)
		}
		// Received some data, assume some Stats were populated.
		if stats.Packets == 0 {
			log.Println("stats indicated 0 received packets")
		}

		log.Printf("- packets: %d, drops: %d, freeze queue count: %d",
			stats.Packets, stats.Drops, stats.FreezeQueueCount)
		// close Conn
		c.Close()
	}()

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
	infinity := count == 0
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
