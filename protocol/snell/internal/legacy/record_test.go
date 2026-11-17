package legacy

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"testing"
)

var testPSK = []byte("legacy-test-password")

func TestRecordsAndZeroChunk(t *testing.T) {
	var wire bytes.Buffer
	w := recordWriter{upstream: &wire, psk: testPSK}
	payload := bytes.Repeat([]byte{0x9f}, maxPayload*2+73)
	if n, err := w.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("write: %d %v", n, err)
	}
	if err := w.writeRecord(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("next")); err != nil {
		t.Fatal(err)
	}
	expected := 16 + len(payload) + 3*34 + 18 + 4 + 34
	if wire.Len() != expected {
		t.Fatalf("wire length %d, want %d", wire.Len(), expected)
	}
	r := recordReader{upstream: &wire, psk: testPSK}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(&r, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload mismatch")
	}
	if _, err := r.Read(got[:1]); !errors.Is(err, errZeroChunk) {
		t.Fatalf("zero chunk: %v", err)
	}
	if _, err := io.ReadFull(&r, got[:4]); err != nil || string(got[:4]) != "next" {
		t.Fatalf("next record: %q %v", got[:4], err)
	}
}

func TestRecordAuthenticationAndTruncation(t *testing.T) {
	var wire bytes.Buffer
	w := recordWriter{upstream: &wire, psk: testPSK}
	w.Write([]byte("authenticated"))
	original := append([]byte(nil), wire.Bytes()...)
	cases := map[string][]byte{
		"short salt": original[:8], "short length": original[:25],
		"short payload": original[:len(original)-1],
	}
	for _, offset := range []int{16, len(original) - 1} {
		bad := append([]byte(nil), original...)
		bad[offset] ^= 1
		cases["corrupt "+hex.EncodeToString([]byte{byte(offset)})] = bad
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			r := recordReader{upstream: bytes.NewReader(data), psk: testPSK}
			if _, err := r.readRecord(); err == nil {
				t.Fatal("accepted invalid record")
			}
			if _, err := r.readRecord(); err == nil {
				t.Fatal("error must be sticky")
			}
		})
	}
	r := recordReader{upstream: bytes.NewReader(original), psk: []byte("wrong password")}
	if _, err := r.readRecord(); err == nil {
		t.Fatal("accepted wrong PSK")
	}
}

type shortWriter struct{ calls int }

func (w *shortWriter) Write(p []byte) (int, error) { w.calls++; return len(p) - 1, nil }

func TestRecordWriteErrors(t *testing.T) {
	sink := new(shortWriter)
	w := recordWriter{upstream: sink, psk: testPSK}
	if _, err := w.Write([]byte("a")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("b")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
	if sink.calls != 1 {
		t.Fatal("retried partially written ciphertext")
	}
	var wire bytes.Buffer
	w = recordWriter{upstream: &wire, psk: testPSK}
	if err := w.writeRecord(make([]byte, maxPayload+1)); err == nil || wire.Len() != 0 {
		t.Fatal("oversized record wrote bytes")
	}
	if n, err := w.Write(nil); n != 0 || err != nil || wire.Len() != 0 {
		t.Fatal("empty Write emitted a termination frame")
	}
}

func TestNonceCarry(t *testing.T) {
	var wire bytes.Buffer
	w := recordWriter{upstream: &wire, psk: testPSK}
	for i := 0; i < 300; i++ {
		if err := w.writeRecord([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	r := recordReader{upstream: &wire, psk: testPSK}
	for i := 0; i < 300; i++ {
		p, err := r.readRecord()
		if err != nil || !bytes.Equal(p, []byte{byte(i)}) {
			t.Fatalf("record %d: %x %v", i, p, err)
		}
	}
	if w.nonce[0] != 88 || w.nonce[1] != 2 {
		t.Fatalf("little endian nonce: %x", w.nonce)
	}
}

// Generated independently by mihomo snell.NewAES128GCM and shadowaead.NewWriter
// at 0455d0d28c4526937380505153e65a843d8612e8, not by this implementation.
func TestMihomoRecordVector(t *testing.T) {
	const vector = "000102030405060708090a0b0c0d0e0f5b7382a900267b2e9a2606349adb6d20bf8ff0f9567298c8b3926af76ca7d4a8ed3b67e69efe697aabdd2e58a42cb351f36d25ca5c78b80a3361d10c8de3ddd54204e7b16a028129b98a3230460d56f7d0d8322d8e29b0d61875077d37c3fce2531dc20642"
	expected, err := hex.DecodeString(vector)
	if err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	salt := expected[:16]
	wire.Write(salt)
	w := recordWriter{upstream: &wire, psk: testPSK, aead: newAEAD(testPSK, salt)}
	if _, err = w.Write([]byte("hello snell")); err != nil {
		t.Fatal(err)
	}
	if err = w.writeRecord(nil); err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write([]byte("next")); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire.Bytes(), expected) {
		t.Fatalf("wire %x, want %x", wire.Bytes(), expected)
	}
	r := recordReader{upstream: bytes.NewReader(expected), psk: testPSK}
	for _, want := range []string{"hello snell", "", "next"} {
		p, err := r.readRecord()
		if want == "" {
			if !errors.Is(err, errZeroChunk) {
				t.Fatal(err)
			}
		} else if err != nil || string(p) != want {
			t.Fatalf("record %q %v", p, err)
		}
	}
}
