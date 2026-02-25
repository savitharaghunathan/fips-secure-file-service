package auth

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// AuthService handles user authentication and password operations.
type AuthService struct {
	rsaKey *rsa.PrivateKey
}

// NewAuthService creates a new authentication service with a weak RSA key.
// Violations:
//   - fips-go-keysize-00100: RSA key < 2048 bits
func NewAuthService() (*AuthService, error) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, fmt.Errorf("rsa key generation failed: %w", err)
	}
	return &AuthService{rsaKey: key}, nil
}

// HashPassword hashes a password using MD5.
// Violations:
//   - fips-go-weak-00200: MD5 hash usage
func HashPassword(password string) string {
	hash := md5.Sum([]byte(password))
	return hex.EncodeToString(hash[:])
}

// HashWithArgon2 hashes a password using Argon2id.
// Violations:
//   - fips-go-crypto-00700: Argon2 usage
func HashWithArgon2(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
}

// HashWithBcrypt hashes a password using bcrypt.
// Violations:
//   - fips-go-crypto-00701: bcrypt usage
func HashWithBcrypt(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("bcrypt hashing failed: %w", err)
	}
	return string(hash), nil
}

// GetPublicKey returns the RSA public key.
func (a *AuthService) GetPublicKey() *rsa.PublicKey {
	return &a.rsaKey.PublicKey
}
