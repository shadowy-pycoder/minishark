package layers

// port 443
type TLSMessage struct{}

func (t *TLSMessage) String() string {
	return ""
}

func (t *TLSMessage) Parse(data []byte) error {
	return nil
}

func (t *TLSMessage) NextLayer() (string, []byte) {
	return "", nil
}
