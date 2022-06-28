package trojan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
)

type Authenticator interface {
	Auth([]byte) ([]byte, bool)
}

type memoryAuth struct {
	list [][]byte
}

func NewMemAuth(pws []string) Authenticator {
	m := &memoryAuth{
		list: make([][]byte, len(pws)),
	}

	for i := range pws {
		m.list[i] = hexSha224([]byte(pws[i]))
	}

	return m
}

func (m *memoryAuth) Auth(pw []byte) ([]byte, bool) {
	for i := range m.list {
		if bytes.Equal(m.list[i], pw) {
			return m.list[i], true
		}
	}
	return nil, false
}

func hexSha224(data []byte) []byte {
	buf := make([]byte, 56)
	hash := sha256.New224()
	hash.Write(data)
	hex.Encode(buf, hash.Sum(nil))
	return buf
}
