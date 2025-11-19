package pdu

import (
	"bytes"
	"testing"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	payload := bytes.Repeat([]byte{0xAA}, 1024)
	buf := new(bytes.Buffer)
	frame := Frame{Type: TypeData, Flags: 0x05, Data: payload}
	if err := Encode(buf, frame); err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	decoded, err := Decode(buf)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if decoded.Type != frame.Type || decoded.Flags != frame.Flags || decoded.Length != uint32(len(payload)) {
		t.Fatalf("header mismatch: %#v", decoded)
	}
	if !bytes.Equal(decoded.Data, payload) {
		t.Fatalf("payload mismatch")
	}
}

func TestDecodeBadMagic(t *testing.T) {
	buf := bytes.NewBuffer([]byte{'X', 'Y', version, TypeData, 0, 0, 0, 0, 0, 0})
	if _, err := Decode(buf); err != ErrBadMagic {
		t.Fatalf("expected ErrBadMagic got %v", err)
	}
}

func TestOversized(t *testing.T) {
	payload := make([]byte, MaxPayload+1)
	if err := Encode(new(bytes.Buffer), Frame{Type: TypeData, Data: payload}); err != ErrOversized {
		t.Fatalf("expected ErrOversized got %v", err)
	}
}
