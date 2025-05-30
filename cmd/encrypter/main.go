// Command cryptutil provides a simple command-line interface for encryption and decryption.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/catalogfi/tools/pkg/cryptutil"
)

func main() {
	// Define command line flags
	decryptMode := flag.Bool("decrypt", false, "Decrypt mode")
	generate := flag.Bool("generate-key", false, "Generate a new random AES-256 key")
	key := flag.String("key", "", "Hex-encoded AES-256 key (64 characters)")
	input := flag.String("input", "", "Input string to encrypt/decrypt")
	flag.Parse()

	// Check for required flags
	if *generate {
		generateKey()
		return
	}

	if *input == "" {
		fmt.Println("Error: No input provided. Use -input flag.")
		printUsage()
		os.Exit(1)
	}

	if *key == "" {
		fmt.Println("Error: No key provided. Use -key flag or generate one with -generate-key.")
		printUsage()
		os.Exit(1)
	}

	// Create a new AES256 instance
	aes, err := cryptutil.NewAES256(*key)
	if err != nil {
		fmt.Printf("Error initializing encryption: %v\n", err)
		os.Exit(1)
	}

	// Process input based on mode
	switch {
	case *decryptMode:
		result, err := aes.DecryptHexToString(*input)
		if err != nil {
			fmt.Printf("Error decrypting: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Decrypted result:", result)

	default: // Default to encrypt mode
		result, err := aes.EncryptStringToHex(*input)
		if err != nil {
			fmt.Printf("Error encrypting: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Encrypted result (hex):", result)
	}
}

// generateKey creates and prints a new random AES-256 key
func generateKey() {
	key := make([]byte, 32) // 32 bytes = 256 bits
	_, err := rand.Read(key)
	if err != nil {
		fmt.Printf("Error generating key: %v\n", err)
		os.Exit(1)
	}

	hexKey := hex.EncodeToString(key)
	fmt.Println("Generated AES-256 key (save this securely):")
	fmt.Println(hexKey)
}

// printUsage prints a more descriptive usage message
func printUsage() {
	fmt.Println("\nUsage examples:")
	fmt.Println("  Generate a new key:")
	fmt.Println("    go run main.go -generate-key")
	fmt.Println("  Encrypt a string:")
	fmt.Println("    go run main.go -key YOUR_KEY -input \"secret message\"")
	fmt.Println("  Decrypt a hex string:")
	fmt.Println("    go run main.go -decrypt -key YOUR_KEY -input ENCRYPTED_HEX_STRING")
}
