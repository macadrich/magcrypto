package magcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
)

// Version module version
func Version() {
	fmt.Println("Version 1.0.0")
}

// GenKeyPair private key generation with Curve25519 Diffie-Hellman function
func GenKeyPair() ([32]byte, [32]byte, error) {
	var pri [32]byte
	var pub [32]byte

	_, err := rand.Read(pri[:])
	if err != nil {
		return pri, pub, err
	}
	pri[0] &= 248
	pri[31] &= 127
	pri[31] |= 64

	curve25519.ScalarBaseMult(&pub, &pri)
	if err != nil {
		return pri, pub, err
	}

	return pri, pub, nil
}

// GenSharedSecret shared secret generation with Curve25519 Diffie-Hellman function
func GenSharedSecret(selfPri, otherPub [32]byte) [32]byte {
	var secret [32]byte
	curve25519.ScalarMult(&secret, &selfPri, &otherPub)
	return secret
}

// Hash HMAC + SHA2 hash function
func Hash(tag string, data []byte) []byte {
	h := hmac.New(sha512.New512_256, []byte(tag))
	h.Write(data)
	return h.Sum(nil)
}

// Encrypt portable encrypt method
func Encrypt(plaintext []byte, secret [32]byte) ([]byte, error) {
	block, err := aes.NewCipher(secret[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt portable decrypt method
func Decrypt(ciphertext []byte, secret [32]byte) ([]byte, error) {
	block, err := aes.NewCipher(secret[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("malformed ciphertext")
	}

	return gcm.Open(nil,
		ciphertext[:gcm.NonceSize()],
		ciphertext[gcm.NonceSize():],
		nil,
	)
}
