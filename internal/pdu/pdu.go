package pdu

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	magic0       = 'U'
	magic1       = 'T'
	version byte = 0x01

	// TypeData carries raw UDP payloads.
	TypeData byte = 0x01

	headerLen  = 2 + 1 + 1 + 1 + 4 // magic + version + type + flags + length
	MaxPayload = 64 * 1024         // 64KiB max UDP payload (per spec)
)

var (
	// ErrBadMagic indicates the frame header magic mismatch.
	ErrBadMagic = errors.New("pdu: bad magic")
	// ErrBadVersion indicates unsupported frame version.
	ErrBadVersion = errors.New("pdu: bad version")
	// ErrOversized indicates payload length beyond MaxPayload.
	ErrOversized = errors.New("pdu: payload too large")
)

// Frame represents a decoded PDU.
type Frame struct {
	Type   byte
	Flags  byte
	Length uint32
	Data   []byte
}

// Encode writes a frame to the supplied writer.
func Encode(w io.Writer, frame Frame) error {
	if len(frame.Data) > MaxPayload {
		return ErrOversized
	}
	hdr := make([]byte, headerLen)
	hdr[0] = magic0
	hdr[1] = magic1
	hdr[2] = version
	hdr[3] = frame.Type
	hdr[4] = frame.Flags
	binary.BigEndian.PutUint32(hdr[5:], uint32(len(frame.Data)))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if len(frame.Data) == 0 {
		return nil
	}
	_, err := w.Write(frame.Data)
	return err
}

// Decode reads a single frame from reader.
func Decode(r io.Reader) (Frame, error) {
	hdr := make([]byte, headerLen)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return Frame{}, err
	}
	if hdr[0] != magic0 || hdr[1] != magic1 {
		return Frame{}, ErrBadMagic
	}
	if hdr[2] != version {
		return Frame{}, ErrBadVersion
	}
	length := binary.BigEndian.Uint32(hdr[5:])
	if length > MaxPayload {
		return Frame{}, fmt.Errorf("pdu: payload len %d exceeds max %d", length, MaxPayload)
	}
	frame := Frame{
		Type:   hdr[3],
		Flags:  hdr[4],
		Length: length,
	}
	if length == 0 {
		return frame, nil
	}
	frame.Data = make([]byte, length)
	if _, err := io.ReadFull(r, frame.Data); err != nil {
		return Frame{}, err
	}
	return frame, nil
}
