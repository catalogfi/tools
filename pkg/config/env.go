package config

import (
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/catalogfi/tools/pkg/cryptutil"
)

// Prefixes used to identify environment variable references in configuration values
const (
	// EnvPrefix is used for environment variables that are read directly
	EnvPrefix = "#ENV:"

	// EncryptedEnvPrefix is used for environment variables that need decryption
	EncryptedEnvPrefix = "#EncryptedENV:"
)

// Parser is responsible for resolving environment variables in configuration data
type Parser struct {
	// AESSecret is the secret key used for decrypting encrypted environment variables
	AESSecret string
}

// NewParser creates a new environment variable parser with the given AES secret key
func NewParser(aesSecret string) *Parser {
	return &Parser{
		AESSecret: aesSecret,
	}
}

// ProcessStruct processes all string fields in a struct, replacing environment variable
// references with their values
func (p *Parser) ProcessStruct(structPtr any) error {
	val := reflect.ValueOf(structPtr)
	if val.Kind() != reflect.Ptr || val.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("expected pointer to struct, got %T", structPtr)
	}

	return p.processStructFields(val.Elem())
}

// processStructFields processes all fields in a struct, handling environment variables in string fields
func (p *Parser) processStructFields(structVal reflect.Value) error {
	for i := 0; i < structVal.NumField(); i++ {
		field := structVal.Field(i)

		if !field.CanInterface() {
			continue // Skip unexported fields
		}

		if err := p.processField(field); err != nil {
			return err
		}
	}
	return nil
}

// processField handles a single field, checking its type and processing accordingly
func (p *Parser) processField(field reflect.Value) error {
	if !field.CanSet() {
		return nil // Skip if field can't be set
	}

	switch field.Kind() {
	case reflect.String:
		if field.String() == "" {
			return nil
		}
		// Process string field for environment variables
		newVal, err := p.processEnvString(field.String())
		if err != nil {
			return err
		}
		if newVal != field.String() {
			field.SetString(newVal)
		}
	case reflect.Struct:
		// Process nested struct
		return p.processStructFields(field)
	case reflect.Ptr:
		// Handle pointers to structs
		if !field.IsNil() && field.Elem().Kind() == reflect.Struct {
			return p.processStructFields(field.Elem())
		}
	case reflect.Map:
		// Process map values
		return p.processMap(field)
	case reflect.Slice:
		// Process slice elements
		return p.processSlice(field)
	}

	return nil
}

// processMap processes all entries in a map
func (p *Parser) processMap(mapField reflect.Value) error {
	for _, key := range mapField.MapKeys() {
		mapValue := mapField.MapIndex(key)

		// For maps, we need to create a new value, process it, and set it back
		switch mapValue.Kind() {
		case reflect.Struct, reflect.Ptr:
			// Make a copy of the value
			tmpValue := reflect.New(mapValue.Type()).Elem()
			tmpValue.Set(mapValue)

			// Process the copy
			if err := p.processField(tmpValue); err != nil {
				return err
			}

			// Set the processed value back into the map
			mapField.SetMapIndex(key, tmpValue)
		case reflect.String:
			// Process string values in the map
			strVal := mapValue.String()
			newVal, err := p.processEnvString(strVal)
			if err != nil {
				return err
			}
			if newVal != strVal {
				mapField.SetMapIndex(key, reflect.ValueOf(newVal))
			}
		}
	}
	return nil
}

// processSlice processes all elements in a slice
func (p *Parser) processSlice(sliceField reflect.Value) error {
	for i := range sliceField.Len() {
		elem := sliceField.Index(i)
		if err := p.processField(elem); err != nil {
			return err
		}
	}
	return nil
}

// processEnvString processes environment variables in a string field
func (p *Parser) processEnvString(value string) (string, error) {
	// Check for environment variable prefix
	if strings.HasPrefix(value, EnvPrefix) {
		envKey := strings.TrimPrefix(value, EnvPrefix)
		return GetEnvValue(envKey)
	} else if strings.HasPrefix(value, EncryptedEnvPrefix) {
		// Handle encrypted environment variables
		envKey := strings.TrimPrefix(value, EncryptedEnvPrefix)
		envValue, err := GetEnvValue(envKey)
		if err != nil {
			return "", err
		}

		return p.decryptEnvValue(envValue)
	}

	// Return original value if no environment variable prefix is found
	return value, nil
}

// decryptEnvValue decrypts an encrypted environment variable value
func (p *Parser) decryptEnvValue(encryptedValue string) (string, error) {
	aesDecryptor, err := cryptutil.NewAES256(p.AESSecret)
	if err != nil {
		return "", fmt.Errorf("failed to create AES decryptor: %w", err)
	}

	return aesDecryptor.DecryptHexToString(encryptedValue)
}

// GetEnvValue retrieves an environment variable value
func GetEnvValue(envKey string) (string, error) {
	envValue := os.Getenv(envKey)
	if envValue == "" {
		return "", fmt.Errorf("environment variable %s not found", envKey)
	}
	return envValue, nil
}
