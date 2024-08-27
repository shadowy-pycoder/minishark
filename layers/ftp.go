package layers

// https://mavlink.io/zh/services/ftp.html
// port 21 port 20
type FTPMessage struct{}

func (f *FTPMessage) String() string {
	return ""
}

func (f *FTPMessage) Parse(data []byte) error {
	return nil
}

func (f *FTPMessage) NextLayer() (string, []byte) {
	return "", nil
}
