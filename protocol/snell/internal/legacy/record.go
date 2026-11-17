// SPDX-License-Identifier: GPL-3.0-or-later
// Snell v2/v3 wire compatibility follows MetaCubeX/mihomo transport/snell
// and transport/shadowsocks/shadowaead (GPL-3.0), revision 0455d0d28c45.
package legacy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
)

const maxPayload = 0x3fff

var errZeroChunk = errors.New("snell: end of reusable stream")

func newAEAD(psk, salt []byte) cipher.AEAD {
	// Derive 32 bytes before truncating: Argon2 output length changes the key.
	key := argon2.IDKey(psk, salt, 3, 8, 1, 32)[:16]
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	return aead
}

func increment(nonce []byte) {
	for i := range nonce {
		nonce[i]++
		if nonce[i] != 0 {
			break
		}
	}
}

type recordWriter struct {
	upstream io.Writer
	psk      []byte
	aead     cipher.AEAD
	nonce    [12]byte
	err      error
}

// writeRecord preserves datagram boundaries. A zero record has only an
// authenticated length, with no payload tag, and consumes one nonce.
func (w *recordWriter) writeRecord(p []byte) error {
	if w.err != nil {
		return w.err
	}
	if len(p) > maxPayload {
		return errors.New("snell: payload too large")
	}
	var out []byte
	if w.aead == nil {
		salt := make([]byte, 16)
		if _, w.err = rand.Read(salt); w.err != nil {
			return w.err
		}
		w.aead = newAEAD(w.psk, salt)
		out = append(out, salt...)
	}
	length := binary.BigEndian.AppendUint16(nil, uint16(len(p)))
	out = w.aead.Seal(out, w.nonce[:], length, nil)
	increment(w.nonce[:])
	if len(p) != 0 {
		out = w.aead.Seal(out, w.nonce[:], p, nil)
		increment(w.nonce[:])
	}
	n, err := w.upstream.Write(out)
	if err == nil && n != len(out) {
		err = io.ErrShortWrite
	}
	w.err = err
	return err
}

func (w *recordWriter) Write(p []byte) (int, error) {
	// Empty application writes do not terminate a reusable stream.
	n := 0
	for len(p) > 0 {
		size := min(len(p), maxPayload)
		if err := w.writeRecord(p[:size]); err != nil {
			return n, err
		}
		n += size
		p = p[size:]
	}
	return n, nil
}

type recordReader struct {
	upstream io.Reader
	psk      []byte
	aead     cipher.AEAD
	nonce    [12]byte
	pending  []byte
	err      error
}

func (r *recordReader) readRecord() ([]byte, error) {
	if r.err != nil {
		return nil, r.err
	}
	p, err := r.read()
	if err != nil && !errors.Is(err, errZeroChunk) {
		r.err = err
	}
	return p, err
}

func (r *recordReader) read() ([]byte, error) {
	if r.aead == nil {
		var salt [16]byte
		if _, err := io.ReadFull(r.upstream, salt[:]); err != nil {
			return nil, err
		}
		r.aead = newAEAD(r.psk, salt[:])
	}
	var length [18]byte
	if _, err := io.ReadFull(r.upstream, length[:]); err != nil {
		return nil, err
	}
	plain, err := r.aead.Open(length[:0], r.nonce[:], length[:], nil)
	if err != nil {
		return nil, err
	}
	increment(r.nonce[:])
	size := int(binary.BigEndian.Uint16(plain)) & maxPayload
	if size == 0 {
		return nil, errZeroChunk
	}
	ciphertext := make([]byte, size+r.aead.Overhead())
	if _, err = io.ReadFull(r.upstream, ciphertext); err != nil {
		return nil, err
	}
	plain, err = r.aead.Open(ciphertext[:0], r.nonce[:], ciphertext, nil)
	if err != nil {
		return nil, err
	}
	increment(r.nonce[:])
	return plain, nil
}

func (r *recordReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(r.pending) == 0 {
		var err error
		r.pending, err = r.readRecord()
		if err != nil {
			return 0, err
		}
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}
