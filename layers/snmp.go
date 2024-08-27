package layers

// https://www.ranecommercial.com/legacy/pdf/ranenotes/SNMP_Simple_Network_Management_Protocol.pdf
// port 161, 162
type SNMPMessage struct{}

func (s *SNMPMessage) String() string {
	return ""
}

func (s *SNMPMessage) Parse(data []byte) error {
	return nil
}

func (s *SNMPMessage) NextLayer() (string, []byte) {
	return "", nil
}
