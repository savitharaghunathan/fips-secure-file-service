package main

import (
	"crypto/rand"
	"fmt"
	"log"

	"github.com/example/secure-file-service/pkg/auth"
	"github.com/example/secure-file-service/pkg/client"
	filecrypto "github.com/example/secure-file-service/pkg/crypto"
)

func main() {
	sampleData := []byte("sensitive-file-contents")

	// Demonstrate weak cipher violations
	encrypted, err := filecrypto.EncryptWithDES(sampleData)
	if err != nil {
		log.Printf("DES encryption failed: %v", err)
	}
	fmt.Printf("DES encrypted: %x\n", encrypted)

	encrypted, err = filecrypto.EncryptWith3DES(sampleData)
	if err != nil {
		log.Printf("3DES encryption failed: %v", err)
	}
	fmt.Printf("3DES encrypted: %x\n", encrypted)

	encrypted, err = filecrypto.EncryptWithRC4(sampleData)
	if err != nil {
		log.Printf("RC4 encryption failed: %v", err)
	}
	fmt.Printf("RC4 encrypted: %x\n", encrypted)

	encrypted, err = filecrypto.EncryptWithBlowfish(sampleData)
	if err != nil {
		log.Printf("Blowfish encryption failed: %v", err)
	}
	fmt.Printf("Blowfish encrypted: %x\n", encrypted)

	encrypted, err = filecrypto.StreamEncryptWithChaCha20(sampleData)
	if err != nil {
		log.Printf("ChaCha20 stream encryption failed: %v", err)
	}
	fmt.Printf("ChaCha20 stream encrypted: %x\n", encrypted)

	// ChaCha20-Poly1305 key size (triggers import-based rule)
	fmt.Printf("ChaCha20-Poly1305 key size: %d\n", filecrypto.ChaCha20Poly1305KeySize)

	// Demonstrate weak hash violations
	blake2bHash := filecrypto.HashWithBlake2b(sampleData)
	fmt.Printf("Blake2b hash: %x\n", blake2bHash)

	blake2sHash := filecrypto.HashWithBlake2s(sampleData)
	fmt.Printf("Blake2s hash: %x\n", blake2sHash)

	// Demonstrate auth violations
	md5Hash := auth.HashPassword("user-password")
	fmt.Printf("MD5 password hash: %s\n", md5Hash)

	salt := make([]byte, 16)
	rand.Read(salt)
	argon2Hash := auth.HashWithArgon2("user-password", salt)
	fmt.Printf("Argon2 hash: %x\n", argon2Hash)

	bcryptHash, err := auth.HashWithBcrypt("user-password")
	if err != nil {
		log.Printf("bcrypt failed: %v", err)
	}
	fmt.Printf("bcrypt hash: %s\n", bcryptHash)

	authSvc, err := auth.NewAuthService()
	if err != nil {
		log.Printf("Auth service creation failed: %v", err)
	}
	fmt.Printf("RSA public key size: %d bits\n", authSvc.GetPublicKey().Size()*8)

	// Demonstrate TLS violations
	tlsCfg := client.InsecureTLSConfig()
	fmt.Printf("InsecureSkipVerify: %v\n", tlsCfg.InsecureSkipVerify)

	db, err := client.ConnectDB()
	if err != nil {
		log.Printf("DB connection failed: %v", err)
	}
	if db != nil {
		db.Close()
	}

	fmt.Println("Secure file service demo complete.")
}
