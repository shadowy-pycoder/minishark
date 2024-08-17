package minishark

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/mdlayher/packet"
	"github.com/packetcap/go-pcap/filter"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

func OpenLive(iface string, snaplen int, promisc bool, timeout time.Duration, count int, expr string) error {

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
	if iface == "any" {
		in = &net.Interface{Index: 0, Name: "any"}
	} else {
		var err error
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
	c.SetPromiscuous(promisc)
	// timeout
	if timeout > 0 {
		c.SetDeadline(time.Now().Add(timeout))
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
	// number of packets
	infinity := count == 0

	for i := 0; infinity || i < count; i++ {
		n, _, err := c.ReadFrom(b)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return nil
			}
			log.Fatalf("failed to read Ethernet frame: %v", err)
		}

		if err := ether.Parse(b[:n]); err != nil {
			log.Fatalln(err)
		}
		fmt.Println(&ether)
		switch ether.NextLayer() {
		case "IPv4":
			if err := ip.Parse(ether.Payload); err != nil {
				log.Fatalln(err)
			}
			fmt.Println(&ip)
			if len(ip.Options) > 0 {
				break
			}
			switch ip.NextLayer() {
			case "TCP":
				if err := tcp.Parse(ip.Payload); err != nil {
					log.Fatalln(err)
				}
				fmt.Println(&tcp)
			case "UDP":
				if err := udp.Parse(ip.Payload); err != nil {
					log.Fatalln(err)
				}
				fmt.Println(&udp)
			case "ICMP":
				if err := icmp.Parse(ip.Payload); err != nil {
					log.Fatalln(err)
				}
				fmt.Println(&icmp)
			}
		case "IPv6":
			if err := ip6.Parse(ether.Payload); err != nil {
				log.Fatalln(err)
			}
			fmt.Println(&ip6)
			switch ip6.NextLayer() {
			case "TCP":
				if err := tcp.Parse(ip6.Payload); err != nil {
					log.Fatalln(err)
				}
				fmt.Println(&tcp)
			case "UDP":
				if err := udp.Parse(ip6.Payload); err != nil {
					log.Fatalln(err)
				}
				fmt.Println(&udp)
			case "ICMPv6":
				if err := icmp6.Parse(ip6.Payload); err != nil {
					log.Fatalln(err)
				}
				fmt.Println(&icmp6)
			}
		case "ARP":
			if err := arp.Parse(ether.Payload); err != nil {
				log.Fatalln(err)
			}
			fmt.Println(&arp)
		}
	}
	return nil
}
