// Package cryptutil provides encryption and decryption utilities using AES-256-GCM.
package cryptutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// Common errors returned by the cryptutil package.
var (
	ErrEmptyData        = errors.New("cryptutil: empty data")
	ErrEmptyKey         = errors.New("cryptutil: empty key")
	ErrInvalidKeyLength = errors.New("cryptutil: invalid key length, must be 32 bytes (64 hex chars) for AES-256")
)

// hexDecode decodes a hex string into bytes.
func hexDecode(hexData string) ([]byte, error) {
	if hexData == "" {
		return nil, ErrEmptyData
	}

	data, err := hex.DecodeString(hexData)
	if err != nil {
		return nil, fmt.Errorf("cryptutil: invalid hex data: %w", err)
	}

	return data, nil
}

// DataEncryptor defines operations for encrypting data.
type DataEncryptor interface {
	// Encrypt takes plaintext data and returns encrypted data.
	Encrypt(data []byte) ([]byte, error)
}

// DataDecryptor defines operations for decrypting data.
type DataDecryptor interface {
	// Decrypt takes encrypted data and returns plaintext data.
	Decrypt(data []byte) ([]byte, error)
}

// AES256 implements both DataEncryptor and DataDecryptor using AES-256-GCM.
// The structure holds the encryption key and provides methods for encryption
// and decryption of data in various formats.
type AES256 struct {
	key []byte
}

// NewAES256 creates a new AES-256 encryption/decryption provider from a hex encoded key.
// The key must be exactly 32 bytes (64 hex characters) for AES-256.
func NewAES256(hexKey string) (*AES256, error) {
	if hexKey == "" {
		return nil, ErrEmptyKey
	}

	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("cryptutil: invalid hex key: %w", err)
	}

	// AES-256 requires a 32-byte key
	if len(key) != 32 {
		return nil, ErrInvalidKeyLength
	}

	return &AES256{key: key}, nil
}

// Encrypt encrypts data using AES-256-GCM.
// The returned data includes the nonce prepended to the ciphertext.
func (a *AES256) Encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, ErrEmptyData
	}

	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, fmt.Errorf("cryptutil: failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cryptutil: failed to create GCM mode: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("cryptutil: failed to generate nonce: %w", err)
	}

	// Seal will append the ciphertext to the nonce, allowing us to store both together
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// EncryptString is a convenience method for encrypting strings.
// It converts the string to bytes and calls Encrypt.
func (a *AES256) EncryptString(plaintext string) ([]byte, error) {
	return a.Encrypt([]byte(plaintext))
}

// EncryptToHex encrypts data and returns it as a hex string.
// This is useful for storing encrypted data in text formats.
func (a *AES256) EncryptToHex(plaintext []byte) (string, error) {
	encrypted, err := a.Encrypt(plaintext)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(encrypted), nil
}

// EncryptStringToHex encrypts a string and returns it as a hex string.
// It's a convenient combination of EncryptString and hex encoding.
func (a *AES256) EncryptStringToHex(plaintext string) (string, error) {
	encrypted, err := a.EncryptString(plaintext)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(encrypted), nil
}

// Decrypt decrypts data using AES-256-GCM.
// It expects the nonce to be prepended to the ciphertext as produced by Encrypt.
func (a *AES256) Decrypt(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, ErrEmptyData
	}

	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, fmt.Errorf("cryptutil: failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cryptutil: failed to create GCM mode: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("cryptutil: encrypted data too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("cryptutil: decryption failed: %w", err)
	}

	return plaintext, nil
}

// DecryptToString is a convenience method for decrypting data to a string.
// It decrypts the data and converts the result to a string.
func (a *AES256) DecryptToString(data []byte) (string, error) {
	plaintext, err := a.Decrypt(data)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// DecryptHex decrypts a hex-encoded string to bytes.
// It first decodes the hex string and then decrypts the result.
func (a *AES256) DecryptHex(hexData string) ([]byte, error) {
	data, err := hexDecode(hexData)
	if err != nil {
		return nil, err
	}
	return a.Decrypt(data)
}

// DecryptHexToString decrypts a hex-encoded string to a string.
// It's a convenient combination of DecryptHex and string conversion.
func (a *AES256) DecryptHexToString(hexData string) (string, error) {
	data, err := hexDecode(hexData)
	if err != nil {
		return "", err
	}
	return a.DecryptToString(data)
}
