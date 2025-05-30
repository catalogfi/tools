// Package cryptutil_test provides tests for the cryptutil package.
package cryptutil_test

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/catalogfi/tools/pkg/cryptutil"
	"github.com/stretchr/testify/require"
)

// TestEncryptAndDecrypt verifies the basic encryption and decryption functionality.
func TestEncryptAndDecrypt(t *testing.T) {
	// Generate a random 32-byte key for AES-256
	encryptionKey := make([]byte, 32)
	_, err := rand.Read(encryptionKey)
	require.NoError(t, err, "failed to generate random encryption key")
	encryptionKeyHex := hex.EncodeToString(encryptionKey)

	// Create a new AES256 encryptor/decryptor
	aes, err := cryptutil.NewAES256(encryptionKeyHex)
	require.NoError(t, err)

	// Test cases
	testCases := []string{
		"",                 // Empty string (should error out during encryption)
		"Simple test data", // Simple string
		"All hail COBI/v2", // Original test case
		"Special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?", // Special characters
		"Unicode: 你好, 世界!",                              // Unicode characters
	}

	for _, tc := range testCases {
		if tc == "" {
			// Empty string should error out
			_, err := aes.EncryptString(tc)
			require.Error(t, err, "empty string should cause an error")
			require.ErrorIs(t, err, cryptutil.ErrEmptyData)
			continue
		}

		// Encrypt the data
		encrypted, err := aes.EncryptString(tc)
		require.NoError(t, err)
		require.NotEmpty(t, encrypted)

		// Decrypt the data
		decrypted, err := aes.DecryptToString(encrypted)
		require.NoError(t, err)
		require.Equal(t, tc, decrypted)

		// Test direct encryption to hex
		hexEncrypted, err := aes.EncryptStringToHex(tc)
		require.NoError(t, err)
		require.NotEmpty(t, hexEncrypted)

		// Decrypt from hex string
		decryptedFromHex, err := aes.DecryptHexToString(hexEncrypted)
		require.NoError(t, err)
		require.Equal(t, tc, decryptedFromHex)

		// Double check that a second encryption produces a different result
		// (due to random nonce)
		encrypted2, err := aes.EncryptString(tc)
		require.NoError(t, err)
		require.NotEqual(t, encrypted, encrypted2,
			"two encryptions of the same data should be different due to random nonce")
	}
}

// TestInvalidKey tests various invalid key scenarios.
func TestInvalidKey(t *testing.T) {
	testCases := []struct {
		name    string
		key     string
		wantErr error
	}{
		{
			name:    "empty key",
			key:     "",
			wantErr: cryptutil.ErrEmptyKey,
		},
		{
			name:    "non-hex key",
			key:     "not-hex-data",
			wantErr: nil, // Just checking for any error, not a specific one
		},
		{
			name:    "short key",
			key:     hex.EncodeToString(make([]byte, 16)), // 16 bytes instead of 32
			wantErr: cryptutil.ErrInvalidKeyLength,
		},
		{
			name:    "long key",
			key:     hex.EncodeToString(make([]byte, 64)), // 64 bytes instead of 32
			wantErr: cryptutil.ErrInvalidKeyLength,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := cryptutil.NewAES256(tc.key)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
			} else {
				require.Error(t, err)
			}
		})
	}
}

// TestEmptyData verifies error handling with empty data.
func TestEmptyData(t *testing.T) {
	// Create AES encryptor for empty data tests
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	aes, err := cryptutil.NewAES256(hex.EncodeToString(key))
	require.NoError(t, err)

	// Test encryption with empty data
	_, err = aes.Encrypt([]byte{})
	require.ErrorIs(t, err, cryptutil.ErrEmptyData)

	// Test decryption with empty data
	_, err = aes.Decrypt([]byte{})
	require.ErrorIs(t, err, cryptutil.ErrEmptyData)

	// Test with too short data for decryption
	tooShortData := []byte{0x01, 0x02, 0x03} // Less than nonce size
	_, err = aes.Decrypt(tooShortData)
	require.Error(t, err)
	require.Contains(t, err.Error(), "too short")
}

// TestDecryptionErrors tests decryption error cases.
func TestDecryptionErrors(t *testing.T) {
	// Create AES encryptor
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	aes, err := cryptutil.NewAES256(hex.EncodeToString(key))
	require.NoError(t, err)

	// Create a different key to demonstrate decryption failure
	differentKey := make([]byte, 32)
	_, err = rand.Read(differentKey)
	require.NoError(t, err)
	differentAes, err := cryptutil.NewAES256(hex.EncodeToString(differentKey))
	require.NoError(t, err)

	// Encrypt with first key
	plaintext := []byte("test data for decryption errors")
	encrypted, err := aes.Encrypt(plaintext)
	require.NoError(t, err)

	// Try to decrypt with different key
	_, err = differentAes.Decrypt(encrypted)
	require.Error(t, err)
	require.Contains(t, err.Error(), "decryption failed")

	// Also test with modified ciphertext
	if len(encrypted) > 0 {
		// Modify a byte in the encrypted data
		corrupted := make([]byte, len(encrypted))
		copy(corrupted, encrypted)
		corrupted[len(corrupted)-1] ^= 0x01 // Flip a bit in the last byte
		_, err = aes.Decrypt(corrupted)
		require.Error(t, err)
		require.Contains(t, err.Error(), "decryption failed")
	}
}

// TestInterface verifies that AES256 implements the DataEncryptor and DataDecryptor interfaces.
func TestInterface(t *testing.T) {
	// Generate a random key
	encryptionKey := make([]byte, 32)
	_, err := rand.Read(encryptionKey)
	require.NoError(t, err)

	// Create the AES instance
	aes, err := cryptutil.NewAES256(hex.EncodeToString(encryptionKey))
	require.NoError(t, err)

	// Verify interface implementation
	var encryptor cryptutil.DataEncryptor = aes
	var decryptor cryptutil.DataDecryptor = aes

	// Test with the interfaces
	originalData := []byte("test data for interface verification")

	encrypted, err := encryptor.Encrypt(originalData)
	require.NoError(t, err)

	decrypted, err := decryptor.Decrypt(encrypted)
	require.NoError(t, err)

	require.Equal(t, originalData, decrypted)
}
