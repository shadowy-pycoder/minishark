package minishark

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"
	"unsafe"
)

// https://wiki.wireshark.org/Development/LibpcapFileFormat/
const (
	magicNumber  uint32 = 0xa1b2c3d4
	versionMajor uint16 = 2
	versionMinor uint16 = 4
	thisZone     int32  = 0
	sigFigs      uint32 = 0
	network      uint32 = 1
)

var nativeEndian binary.ByteOrder

func init() {
	// https://stackoverflow.com/questions/51332658/any-better-way-to-check-endianness-in-go
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)

	switch buf {
	case [2]byte{0xCD, 0xAB}:
		nativeEndian = binary.LittleEndian
	case [2]byte{0xAB, 0xCD}:
		nativeEndian = binary.BigEndian
	default:
		panic("Could not determine native endianness.")
	}
}

type pcapWriter struct {
	w   io.Writer
	buf [16]byte
}

func NewPcapWriter(w io.Writer) *pcapWriter {
	return &pcapWriter{w: w}
}

func (pw *pcapWriter) WriteGlobalHeader(snaplen int32) error {
	var buf [24]byte
	nativeEndian.PutUint32(buf[0:4], magicNumber)
	nativeEndian.PutUint16(buf[4:6], versionMajor)
	nativeEndian.PutUint16(buf[6:8], versionMinor)
	nativeEndian.PutUint32(buf[8:12], uint32(thisZone))
	nativeEndian.PutUint32(buf[12:16], sigFigs)
	nativeEndian.PutUint32(buf[16:20], uint32(snaplen))
	nativeEndian.PutUint32(buf[20:24], network)
	_, err := pw.w.Write(buf[:])
	return err
}

func (pw *pcapWriter) writePacketHeader(timestamp time.Time, packetLen int) error {
	secs := timestamp.Unix()
	msecs := timestamp.Nanosecond() / 1e6
	nativeEndian.PutUint32(pw.buf[0:4], uint32(secs))
	nativeEndian.PutUint32(pw.buf[4:8], uint32(msecs))
	nativeEndian.PutUint32(pw.buf[8:12], uint32(packetLen))
	nativeEndian.PutUint32(pw.buf[12:16], uint32(packetLen))
	_, err := pw.w.Write(pw.buf[:])
	return err
}

func (pw *pcapWriter) WritePacket(timestamp time.Time, data []byte) error {
	if err := pw.writePacketHeader(timestamp, len(data)); err != nil {
		return fmt.Errorf("error writing packet header: %v", err)
	}
	_, err := pw.w.Write(data)
	return err
}
