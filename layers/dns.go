package layers

// https://en.wikipedia.org/wiki/Domain_Name_System
// port 53
type DNSMessage struct{}

func (d *DNSMessage) String() string {
	return ""
}

func (d *DNSMessage) Parse(data []byte) error {
	return nil
}

func (d *DNSMessage) NextLayer() (string, []byte) {
	return "", nil
}
