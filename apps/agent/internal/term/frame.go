// Package term implements the web-terminal session type (ADR-0023).
//
// The agent doctrine is "no exec() primitive" (agent spec §4 preamble): every
// mutation is a named, signed method. A terminal is an admission of reality —
// operators will shell into the node — and the doctrine survives by making it
// a NAMED capability instead of a hole: the control plane sends one signed
// `terminal.open` envelope per session (same Ed25519 envelope as every other
// method), the agent refuses it unless it was wired in at launch time, every
// open/close lands in the hash-chained audit trail, and the session itself
// carries no command channel beyond the pty bytes.
package term

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Frame types (ADR-0023 wire protocol). The namespace is shared across both
// directions; the sender for each type is noted.
type Frame byte

const (
	FrameInput  Frame = 0x01 // client → agent: raw stdin bytes
	FrameResize Frame = 0x02 // client → agent: 4 bytes, cols/rows uint16 BE
	FramePing   Frame = 0x03 // client → agent: keepalive, no payload
	FrameOutput Frame = 0x10 // agent → client: raw pty bytes
	FrameExit   Frame = 0x11 // agent → client: JSON {"status":N,"reason":"…"}
	FrameError  Frame = 0x12 // agent → client: JSON {"message":"…"}
)

// maxFrameSize caps one frame payload in either direction. Keystroke-driven
// input never approaches it; output is chunked to it. The cap bounds the
// memory a single malicious/buggy peer can make the agent buffer.
const maxFrameSize = 64 << 10

var errFrameTooLarge = fmt.Errorf("frame payload exceeds %d bytes", maxFrameSize)

// WriteFrame writes one frame: type byte, uint32 BE length, payload.
func WriteFrame(w io.Writer, t Frame, payload []byte) error {
	if len(payload) > maxFrameSize {
		return errFrameTooLarge
	}
	hdr := [5]byte{byte(t)}
	binary.BigEndian.PutUint32(hdr[1:5], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := w.Write(payload)
	return err
}

// ReadFrame reads one frame from r. Each call allocates its payload — input
// frames are keystroke-sized, so the cost is negligible next to the pty reads.
func ReadFrame(r io.Reader) (Frame, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	t := Frame(hdr[0])
	n := binary.BigEndian.Uint32(hdr[1:5])
	if n > maxFrameSize {
		return t, nil, errFrameTooLarge
	}
	payload := make([]byte, n)
	if n == 0 {
		return t, payload, nil
	}
	if _, err := io.ReadFull(r, payload); err != nil {
		return t, nil, err
	}
	return t, payload, nil
}
