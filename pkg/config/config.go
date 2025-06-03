package config

import (
	"encoding/json"
	"fmt"
	"os"
)

func LoadFromFile(filePath, secret string, target interface{}) error {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return fmt.Errorf("file not exists")
	}
	file, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(file, target); err != nil {
		return err
	}

	// Parse the file when it contains confidential values can only be fetched from ENV
	parser := NewParser(secret)
	if err := parser.ProcessStruct(target); err != nil {
		return err
	}

	return nil
}
