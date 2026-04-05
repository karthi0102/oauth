package cryptoutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
)

// GenerateKey generates a new RSA private key of 2048 bits.
func GenerateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// SaveKeyToFile saves the given RSA private key to the specified path in PEM format.
func SaveKeyToFile(key *rsa.PrivateKey, path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	privASN1 := x509.MarshalPKCS1PrivateKey(key)
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privASN1,
	}

	return pem.Encode(file, pemBlock)
}

// LoadKeyFromFile loads an RSA private key from the specified path.
// If the file does not exist, it generates a new key, saves it to the path, and returns it.
func LoadKeyFromFile(path string) (*rsa.PrivateKey, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		key, err := GenerateKey()
		if err != nil {
			return nil, err
		}
		if err := SaveKeyToFile(key, path); err != nil {
			return nil, err
		}
		return key, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode PEM block from file")
	}

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privKey, nil
}