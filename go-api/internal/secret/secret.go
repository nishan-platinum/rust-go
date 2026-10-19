// Package secret encrypts tenant database passwords at rest with AES-256-GCM.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

type Box struct{ aead cipher.AEAD }

func New(key []byte) (*Box, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

// Seal encrypts plaintext. The tenant id is bound in as associated data, so a
// ciphertext copied onto another tenant's row will fail to decrypt.
func (b *Box) Seal(plaintext, tenantID string) ([]byte, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return b.aead.Seal(nonce, nonce, []byte(plaintext), []byte(tenantID)), nil
}

func (b *Box) Open(ciphertext []byte, tenantID string) (string, error) {
	n := b.aead.NonceSize()
	if len(ciphertext) < n {
		return "", errors.New("ciphertext too short")
	}
	pt, err := b.aead.Open(nil, ciphertext[:n], ciphertext[n:], []byte(tenantID))
	if err != nil {
		return "", errors.New("decrypt failed (wrong key or tampered row)")
	}
	return string(pt), nil
}
