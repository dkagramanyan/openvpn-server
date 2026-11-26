package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// A minimal CBOR decoder (RFC 8949, definite lengths only): enough to read the
// WebAuthn attestation object a device sends for device-attest-01.
type cborReader struct {
	b []byte
	i int
}

var errCBOR = errors.New("malformed CBOR")

func decodeCBOR(b []byte) (any, error) {
	r := &cborReader{b: b}
	v, err := r.item(0)
	if err == nil && r.i != len(b) {
		err = fmt.Errorf("%w: %d trailing bytes", errCBOR, len(b)-r.i)
	}
	return v, err
}

func (r *cborReader) take(n uint64) ([]byte, error) {
	if n > uint64(len(r.b)-r.i) {
		return nil, errCBOR
	}
	out := r.b[r.i : r.i+int(n)]
	r.i += int(n)
	return out, nil
}

func (r *cborReader) head() (byte, uint64, error) {
	b, err := r.take(1)
	if err != nil {
		return 0, 0, err
	}
	major, info := b[0]>>5, b[0]&31
	switch {
	case info < 24:
		return major, uint64(info), nil
	case info <= 27:
		v, err := r.take(1 << (info - 24))
		if err != nil {
			return 0, 0, err
		}
		var n uint64
		for _, c := range v {
			n = n<<8 | uint64(c)
		}
		return major, n, nil
	}
	return 0, 0, fmt.Errorf("%w: indefinite length", errCBOR)
}

func (r *cborReader) item(depth int) (any, error) {
	if depth > 32 {
		return nil, errCBOR
	}
	start := r.i
	major, n, err := r.head()
	if err != nil {
		return nil, err
	}
	switch major {
	case 0:
		return n, nil
	case 1:
		return -1 - int64(n), nil
	case 2:
		return r.take(n)
	case 3:
		s, err := r.take(n)
		return string(s), err
	case 4:
		if n > uint64(len(r.b)) {
			return nil, errCBOR
		}
		out := make([]any, 0, n)
		for range n {
			v, err := r.item(depth + 1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case 5:
		if n > uint64(len(r.b)) {
			return nil, errCBOR
		}
		out := make(map[string]any, n)
		for range n {
			k, err := r.item(depth + 1)
			if err != nil {
				return nil, err
			}
			v, err := r.item(depth + 1)
			if err != nil {
				return nil, err
			}
			out[fmt.Sprint(k)] = v
		}
		return out, nil
	case 6:
		return r.item(depth + 1) // tag: keep the content
	case 7:
		switch r.b[start] & 31 {
		case 20:
			return false, nil
		case 21:
			return true, nil
		case 22, 23:
			return nil, nil
		case 26:
			return float64(math.Float32frombits(uint32(n))), nil
		case 27:
			return math.Float64frombits(binary.BigEndian.Uint64(r.b[r.i-8 : r.i])), nil
		}
	}
	return nil, fmt.Errorf("%w: major %d", errCBOR, major)
}
