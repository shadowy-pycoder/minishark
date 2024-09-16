package layers

import (
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func BenchmarkParseSSH(b *testing.B) {
	packet, close := testPacketBench(b, "ssh")
	defer close()
	b.ResetTimer()
	ssh := &SSHMessage{}
	for i := 0; i < b.N; i++ {
		_ = ssh.Parse(packet)
		fmt.Fprint(io.Discard, ssh.String())
	}
}

func TestParseSSHProtoEx(t *testing.T) {
	expected := &SSHMessage{Protocol: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"}
	ssh := &SSHMessage{}
	packet, close := testPacket(t, "ssh_proto_ex")
	defer close()
	if err := ssh.Parse(packet); err != nil {
		t.Fatal(err)
	}
	require.Equal(t, expected, ssh)
}

func TestParseSSHKeyExInitClient(t *testing.T) {
	expected := &SSHMessage{Messages: []*Message{
		{
			PacketLength:     1532,
			PaddingLength:    7,
			MesssageType:     20,
			MesssageTypeDesc: "Key Exchange Init",
		},
	}}
	ssh := &SSHMessage{}
	packet, close := testPacket(t, "ssh_client_kex_init")
	defer close()
	if err := ssh.Parse(packet); err != nil {
		t.Fatal(err)
	}
	require.Equal(t, len(expected.Messages), len(ssh.Messages))
	require.Equal(t, expected.Messages[0].PacketLength, ssh.Messages[0].PacketLength)
	require.Equal(t, expected.Messages[0].PaddingLength, ssh.Messages[0].PaddingLength)
	require.Equal(t, expected.Messages[0].MesssageType, ssh.Messages[0].MesssageType)
	require.Equal(t, expected.Messages[0].MesssageTypeDesc, ssh.Messages[0].MesssageTypeDesc)
}

func TestParseSSHKeyExInitServer(t *testing.T) {
	expected := &SSHMessage{Messages: []*Message{
		{
			PacketLength:     1108,
			PaddingLength:    10,
			MesssageType:     20,
			MesssageTypeDesc: "Key Exchange Init",
		},
	}}
	ssh := &SSHMessage{}
	packet, close := testPacket(t, "ssh_server_kex_init")
	defer close()
	if err := ssh.Parse(packet); err != nil {
		t.Fatal(err)
	}
	require.Equal(t, len(expected.Messages), len(ssh.Messages))
	require.Equal(t, expected.Messages[0].PacketLength, ssh.Messages[0].PacketLength)
	require.Equal(t, expected.Messages[0].PaddingLength, ssh.Messages[0].PaddingLength)
	require.Equal(t, expected.Messages[0].MesssageType, ssh.Messages[0].MesssageType)
	require.Equal(t, expected.Messages[0].MesssageTypeDesc, ssh.Messages[0].MesssageTypeDesc)
}

func TestParseSSHKeyExDHClient(t *testing.T) {
	expected := &SSHMessage{Messages: []*Message{
		{
			PacketLength:     44,
			PaddingLength:    6,
			MesssageType:     30,
			MesssageTypeDesc: "Elliptic Curve Diffie-Hellman Key Exchange Init",
		},
	}}
	ssh := &SSHMessage{}
	packet, close := testPacket(t, "ssh_client_dh_kex")
	defer close()
	if err := ssh.Parse(packet); err != nil {
		t.Fatal(err)
	}
	require.Equal(t, len(expected.Messages), len(ssh.Messages))
	require.Equal(t, expected.Messages[0].PacketLength, ssh.Messages[0].PacketLength)
	require.Equal(t, expected.Messages[0].PaddingLength, ssh.Messages[0].PaddingLength)
	require.Equal(t, expected.Messages[0].MesssageType, ssh.Messages[0].MesssageType)
	require.Equal(t, expected.Messages[0].MesssageTypeDesc, ssh.Messages[0].MesssageTypeDesc)
}

func TestParseSSHKeyExDHServer(t *testing.T) {
	expected := &SSHMessage{Messages: []*Message{
		{
			PacketLength:     188,
			PaddingLength:    8,
			MesssageType:     31,
			MesssageTypeDesc: "Elliptic Curve Diffie-Hellman Key Exchange Reply",
		},
		{
			PacketLength:     12,
			PaddingLength:    10,
			MesssageType:     21,
			MesssageTypeDesc: "New Keys",
		},
		{},
	}}
	ssh := &SSHMessage{}
	packet, close := testPacket(t, "ssh_server_dh_kex")
	defer close()
	if err := ssh.Parse(packet); err != nil {
		t.Fatal(err)
	}
	require.Equal(t, len(expected.Messages), len(ssh.Messages))
	for i := range expected.Messages {
		require.Equal(t, expected.Messages[i].PacketLength, ssh.Messages[i].PacketLength)
		require.Equal(t, expected.Messages[i].PaddingLength, ssh.Messages[i].PaddingLength)
		require.Equal(t, expected.Messages[i].MesssageType, ssh.Messages[i].MesssageType)
		require.Equal(t, expected.Messages[i].MesssageTypeDesc, ssh.Messages[i].MesssageTypeDesc)
	}
}

func TestParseSSHNewKeysClient(t *testing.T) {
	expected := &SSHMessage{Messages: []*Message{
		{
			PacketLength:     12,
			PaddingLength:    10,
			MesssageType:     21,
			MesssageTypeDesc: "New Keys",
		},
	}}
	ssh := &SSHMessage{}
	packet, close := testPacket(t, "ssh_client_new_keys")
	defer close()
	if err := ssh.Parse(packet); err != nil {
		t.Fatal(err)
	}
	require.Equal(t, len(expected.Messages), len(ssh.Messages))
	require.Equal(t, expected.Messages[0].PacketLength, ssh.Messages[0].PacketLength)
	require.Equal(t, expected.Messages[0].PaddingLength, ssh.Messages[0].PaddingLength)
	require.Equal(t, expected.Messages[0].MesssageType, ssh.Messages[0].MesssageType)
	require.Equal(t, expected.Messages[0].MesssageTypeDesc, ssh.Messages[0].MesssageTypeDesc)
}
