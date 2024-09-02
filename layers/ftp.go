package layers

import "fmt"

type FTPMessage struct {
	payload string
}

func (f *FTPMessage) String() string {
	return fmt.Sprintf(`%s
%s`, f.Summary(), f.payload)
}

func (f *FTPMessage) Summary() string {
	return fmt.Sprint("FTP Message:")
}

func (f *FTPMessage) Parse(data []byte) error {
	f.payload = bytesToStr(data)
	return nil
}

func (f *FTPMessage) NextLayer() (string, []byte) {
	return "", nil
}
