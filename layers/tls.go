package layers

import "fmt"

// port 443
type TLSMessage struct{}

func (s *TLSMessage) String() string {
	return fmt.Sprintf(`%s`, s.Summary())
}

func (s *TLSMessage) Summary() string {
	return fmt.Sprint("TLS Message:")
}
func (t *TLSMessage) Parse(data []byte) error {
	return nil
}

func (t *TLSMessage) NextLayer() (string, []byte) {
	return "", nil
}
