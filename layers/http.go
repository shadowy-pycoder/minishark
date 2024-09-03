package layers

import (
	"bytes"
	"fmt"
)

// https://developer.mozilla.org/en-US/docs/Web/HTTP/Messages
// port 80
type HTTPMessage struct {
	summary []byte
	data    []byte
}

func (h *HTTPMessage) String() string {
	return fmt.Sprintf(`%s
%s
`, h.Summary(), h.data)
}
func (h *HTTPMessage) Summary() string {
	return fmt.Sprintf("HTTP Message: %s", h.summary)
}

func (h *HTTPMessage) ellipsify() {
	h.summary = ellipsis
	h.data = ellipsis
}

func (h *HTTPMessage) Parse(data []byte) error {

	if !bytes.Contains(data, proto) {
		h.ellipsify()
		return nil
	}

	var idx int
	if idx = bytes.Index(data, dcrlf); idx == -1 {
		h.ellipsify()
		return nil
	}

	sp := bytes.Split(data[:idx], crlf)
	lsp := len(sp)
	switch {
	case lsp > 2:
		h.summary = bytes.Join(sp[:2], bspace)
		sp[0] = joinBytes(dash, sp[0])
		h.data = bytes.TrimSuffix(bytes.Join(sp, lfd), crlf)
	case lsp > 1:
		h.summary = sp[0]
		sp[0] = joinBytes(dash, sp[0])
		h.data = bytes.TrimSuffix(bytes.Join(sp, lfd), crlf)
	default:
		h.ellipsify()
	}
	return nil
}

func (h *HTTPMessage) NextLayer() (string, []byte) {
	return "", nil
}
