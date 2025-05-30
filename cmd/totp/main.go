package main

import (
	"bytes"
	"flag"
	"fmt"
	"image/png"
	"os"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func main() {
	accountName := flag.String("account", "", "account name")
	flag.Parse()

	key, err := GenerateSecret(*accountName)
	if err != nil {
		panic(err)
	}
	if err := Display(key); err != nil {
		panic(err)
	}
}

// GenerateSecret generates a new random secret key with optional parameters
func GenerateSecret(accountName string) (*otp.Key, error) {
	return totp.Generate(totp.GenerateOpts{
		Issuer:      "moji",
		AccountName: accountName,
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
}

// Display the key in a qr code image
func Display(key *otp.Key) error {
	var buf bytes.Buffer
	img, err := key.Image(200, 200)
	if err != nil {
		return err
	}
	if err := png.Encode(&buf, img); err != nil {
		return err
	}
	key.URL()

	fmt.Printf("Issuer:       %s\n", key.Issuer())
	fmt.Printf("Account Name: %s\n", key.AccountName())
	fmt.Printf("Secret:       %s\n", key.Secret())
	fmt.Printf("URL   :       %s\n", key.URL())
	fmt.Println("Writing PNG to qr-code.png....")
	if err := os.WriteFile("qr-code.png", buf.Bytes(), 0644); err != nil {
		return err
	}
	fmt.Println("")
	fmt.Println("Please add your TOTP to your OTP Application now!")
	fmt.Println("")
	return nil
}
