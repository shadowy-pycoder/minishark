package mshark

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/mdlayher/packet"
	"github.com/packetcap/go-pcap/filter"
	"github.com/shadowy-pycoder/mshark/layers"
	"golang.org/x/net/bpf"
)

const unixEthPAll int = 0x03

var colorMap = map[int]string{
	0: "\033[37m",
	1: "\033[36m",
	2: "\033[32m",
	3: "\033[33m",
	4: "\033[35m",
}

var _ PacketWriter = &Writer{}

type PacketWriter interface {
	WritePacket(timestamp time.Time, data []byte) error
}

type Config struct {
	Device      *net.Interface // The name of the network interface ("any" means listen on all interfaces).
	Snaplen     int            // The maximum length of each packet snapshot.
	Promisc     bool           // Promiscuous mode. This setting is ignored for "any" interface.
	Timeout     time.Duration  // The maximum duration of the packet capture process.
	PacketCount int            // The maximum number of packets to capture.
	Expr        string         // BPF filter expression.
}

type Writer struct {
	w       io.Writer
	packets uint64
	stdout  bool
}

// NewWriter creates a new mshark Writer.
func NewWriter(w io.Writer) *Writer {
	var stdout bool
	if w == os.Stdout {
		stdout = true
	}
	return &Writer{w: w, stdout: stdout}
}

// printPacket prints a layer packet to the writer. If the writer is an instance of os.Stdout,
// the packet will be printed with color, based on the layerNum.
func (mw *Writer) printPacket(layer layers.Layer, layerNum int) {
	packet := layer.String()
	if mw.stdout {
		if color, ok := colorMap[layerNum]; ok {
			packet = color + packet + "\033[0m"
		}
	}
	fmt.Fprintln(mw.w, packet)
}

// WritePacket writes a packet to the writer, along with its timestamp.
//
// Timestamps are to be generated by the calling code.
func (mw *Writer) WritePacket(timestamp time.Time, data []byte) error {
	mw.packets++
	fmt.Fprintf(mw.w, "- Packet: %d Timestamp: %s\n", mw.packets, timestamp.Format("2006-01-02T15:04:05-0700"))
	fmt.Fprintln(mw.w, "==================================================================")
	next := layers.LayerMap["ETH"]
	if err := next.Parse(data); err != nil {
		return err
	}
	var layerNum int
	mw.printPacket(next, layerNum)
	for {
		name, data := next.NextLayer()
		if name == "" {
			return nil
		}
		next = layers.LayerMap[name]
		if err := next.Parse(data); err != nil {
			return err
		}
		layerNum++
		mw.printPacket(next, layerNum)
	}
}

// WriteHeader writes a header to the writer.
//
// The header contains metadata about the capture, such as the interface name,
// snapshot length, promiscuous mode, timeout, number of packets, and BPF filter.
//
// The header is written in the following format:
//
//   - Interface: eth0
//   - Snapshot Length: 65535
//   - Promiscuous Mode: true
//   - Timeout: 5s
//   - Number of Packets: 0
//   - BPF Filter: "ip proto tcp"
func (mw *Writer) WriteHeader(c *Config) error {
	_, err := fmt.Fprintf(mw.w, `- Interface: %s
- Snapshot Length: %d
- Promiscuous Mode: %v
- Timeout: %s
- Number of Packets: %d
- BPF Filter: %q

`,
		c.Device.Name,
		c.Snaplen,
		c.Device.Name != "any" && c.Promisc,
		c.Timeout,
		c.PacketCount,
		c.Expr,
	)
	return err
}

// InterfaceByName returns the interface specified by name.
func InterfaceByName(name string) (*net.Interface, error) {
	var (
		in  *net.Interface
		err error
	)
	if name == "any" {
		in = &net.Interface{Index: 0, Name: "any"}
	} else {
		in, err = net.InterfaceByName(name)
		if err != nil {
			return nil, fmt.Errorf("unknown interface %s: %v", name, err)
		}
		ok := true &&
			// Look for an Ethernet interface.
			len(in.HardwareAddr) == 6 &&
			// Look for up, multicast, broadcast.
			in.Flags&(net.FlagUp|net.FlagMulticast|net.FlagBroadcast) != 0
		if !ok {
			return nil, fmt.Errorf("interface %s is not up", name)
		}
	}
	return in, nil
}

// OpenLive opens a live capture based on the given configuration and writes
// all captured packets to the given PacketWriters.
func OpenLive(conf *Config, pw ...PacketWriter) error {

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

	// opening connection
	c, err := packet.Listen(conf.Device, packet.Raw, unixEthPAll, &packetcfg)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return fmt.Errorf("permission denied (try setting CAP_NET_RAW capability): %v", err)
		}
		return fmt.Errorf("failed to listen: %v", err)
	}

	// setting promisc mode
	if conf.Device.Name != "any" {
		if err := c.SetPromiscuous(conf.Promisc); err != nil {
			return fmt.Errorf("unable to set promiscuous mode: %v", err)
		}
	}

	// timeout
	if conf.Timeout > 0 {
		if err := c.SetDeadline(time.Now().Add(conf.Timeout)); err != nil {
			return fmt.Errorf("unable to set timeout: %v", err)
		}
	}

	defer func() {
		stats, err := c.Stats()
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to fetch stats: %v", err)
		} else {
			fmt.Printf("- Packets: %d, Drops: %d, Freeze Queue Count: %d\n",
				stats.Packets, stats.Drops, stats.FreezeQueueCount)
			for _, w := range pw {
				if w, ok := w.(*Writer); ok {
					fmt.Fprintf(w.w, "- Packets Captured: %d\n", w.packets)
				}
			}
		}
		// close Conn
		c.Close()
	}()

	// number of packets
	count := conf.PacketCount
	if count < 0 {
		count = 0
	}
	infinity := count == 0

	b := make([]byte, conf.Snaplen)

	for i := 0; infinity || i < count; i++ {
		n, _, err := c.ReadFrom(b)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return nil
			}
			return fmt.Errorf("failed to read Ethernet frame: %v", err)
		}
		for _, w := range pw {
			if err := w.WritePacket(time.Now().UTC(), b[:n]); err != nil {
				return err
			}
		}
	}
	return nil
}
