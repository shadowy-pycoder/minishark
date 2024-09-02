package layers

import "fmt"

// https://www.omnisecu.com/tcpip/ssh-packet-format.php
// port 22
type SSHMessage struct{}

func (s *SSHMessage) String() string {
	return fmt.Sprintf(`%s`, s.Summary())
}

func (s *SSHMessage) Summary() string {
	return fmt.Sprint("SSH Message:")
}

func (s *SSHMessage) Parse(data []byte) error {
	return nil
}

func (s *SSHMessage) NextLayer() (string, []byte) {
	return "", nil
}
