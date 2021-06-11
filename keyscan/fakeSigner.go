package keyscan

import (
	"errors"
	"io"

	"golang.org/x/crypto/ssh"
)

type fakeSigner struct {
	key ssh.PublicKey
}

func (f *fakeSigner) PublicKey() ssh.PublicKey {
	return f.key
}

func (f *fakeSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return nil, errors.New("fakeSigned")
}
