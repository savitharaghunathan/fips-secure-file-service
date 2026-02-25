package crypto

import (
	"crypto/des"
	"crypto/rc4"
	"fmt"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

// ChaCha20Poly1305KeySize exports the key size to confirm the import is referenced.
// Violations:
//   - fips-go-crypto-00400: ChaCha20-Poly1305 usage (via import)
var ChaCha20Poly1305KeySize = chacha20poly1305.KeySize

// EncryptWithDES encrypts data using DES with a hardcoded key.
// Violations:
//   - fips-go-weak-00100: DES cipher usage
//   - fips-go-ops-00100: Hardcoded cryptographic key
func EncryptWithDES(data []byte) ([]byte, error) {
	block, err := des.NewCipher([]byte("8bytekey"))
	if err != nil {
		return nil, fmt.Errorf("des cipher creation failed: %w", err)
	}

	padded := pkcs5Pad(data, block.BlockSize())
	ciphertext := make([]byte, len(padded))
	for i := 0; i < len(padded); i += block.BlockSize() {
		block.Encrypt(ciphertext[i:i+block.BlockSize()], padded[i:i+block.BlockSize()])
	}

	return ciphertext, nil
}

// EncryptWith3DES encrypts data using Triple DES with a hardcoded key.
// Violations:
//   - fips-go-weak-00101: 3DES cipher usage
func EncryptWith3DES(data []byte) ([]byte, error) {
	key := []byte("123456789012345678901234")
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, fmt.Errorf("3des cipher creation failed: %w", err)
	}

	padded := pkcs5Pad(data, block.BlockSize())
	ciphertext := make([]byte, len(padded))
	for i := 0; i < len(padded); i += block.BlockSize() {
		block.Encrypt(ciphertext[i:i+block.BlockSize()], padded[i:i+block.BlockSize()])
	}

	return ciphertext, nil
}

// EncryptWithRC4 encrypts data using the RC4 stream cipher.
// Violations:
//   - fips-go-weak-00102: RC4 cipher usage
func EncryptWithRC4(data []byte) ([]byte, error) {
	c, err := rc4.NewCipher([]byte("rc4-secret-key!!"))
	if err != nil {
		return nil, fmt.Errorf("rc4 cipher creation failed: %w", err)
	}

	ciphertext := make([]byte, len(data))
	c.XORKeyStream(ciphertext, data)
	return ciphertext, nil
}

// EncryptWithBlowfish encrypts data using the Blowfish cipher.
// Violations:
//   - fips-go-crypto-00200: Blowfish cipher usage
func EncryptWithBlowfish(data []byte) ([]byte, error) {
	key := []byte("blowfish-key-material!")
	c, err := blowfish.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("blowfish cipher creation failed: %w", err)
	}

	if len(data) < 8 {
		data = pkcs5Pad(data, 8)
	}
	ciphertext := make([]byte, 8)
	c.Encrypt(ciphertext, data[:8])
	return ciphertext, nil
}

// StreamEncryptWithChaCha20 encrypts data using the ChaCha20 stream cipher.
// Violations:
//   - fips-go-crypto-00300: ChaCha20 stream cipher usage
func StreamEncryptWithChaCha20(data []byte) ([]byte, error) {
	key := make([]byte, chacha20.KeySize)
	copy(key, []byte("chacha20-stream-cipher-key!"))
	nonce := make([]byte, chacha20.NonceSize)

	c, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return nil, fmt.Errorf("chacha20 creation failed: %w", err)
	}

	ciphertext := make([]byte, len(data))
	c.XORKeyStream(ciphertext, data)
	return ciphertext, nil
}

// HashWithBlake2b hashes data using the Blake2b hash function.
// Violations:
//   - fips-go-crypto-00600: Blake2b hash usage
func HashWithBlake2b(data []byte) []byte {
	hash := blake2b.Sum256(data)
	return hash[:]
}

// HashWithBlake2s hashes data using the Blake2s hash function.
// Violations:
//   - fips-go-crypto-00601: Blake2s hash usage
func HashWithBlake2s(data []byte) []byte {
	hash := blake2s.Sum256(data)
	return hash[:]
}

func pkcs5Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := make([]byte, padding)
	for i := range padtext {
		padtext[i] = byte(padding)
	}
	return append(data, padtext...)
}
