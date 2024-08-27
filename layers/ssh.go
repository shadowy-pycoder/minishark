package layers

// https://www.omnisecu.com/tcpip/ssh-packet-format.php
// port 22
type SSHMessage struct{}

func (s *SSHMessage) String() string {
	return ""
}

func (s *SSHMessage) Parse(data []byte) error {
	return nil
}

func (s *SSHMessage) NextLayer() (string, []byte) {
	return "", nil
}
