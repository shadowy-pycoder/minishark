package layers

// https://developer.mozilla.org/en-US/docs/Web/HTTP/Messages
// port 80
type HTTPMessage struct{}

func (h *HTTPMessage) String() string {
	return ""
}

func (h *HTTPMessage) Parse(data []byte) error {
	return nil
}

func (h *HTTPMessage) NextLayer() (string, []byte) {
	return "", nil
}
