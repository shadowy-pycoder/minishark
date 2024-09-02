package layers

import "fmt"

type FTPMessage struct {
	payload string
}

func (f *FTPMessage) String() string {
	return fmt.Sprintf(`FTP Message:
%s
`, f.payload)
}

func (f *FTPMessage) Parse(data []byte) error {
	f.payload = bytesToStr(data)
	return nil
}

func (f *FTPMessage) NextLayer() (string, []byte) {
	return "", nil
}
