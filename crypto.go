package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/mldsa"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
)

const keyLen = 32

// Keys contains a user's key material
type Keys struct {
	RSAPrivate string // PEM
	ECCPrivate []byte // raw seed
	dsaKey     *mldsa.PrivateKey
	kemKey     *mlkem.DecapsulationKey768
}

// CBOMs: yes
// cdxgen
// CBOMkit-hyperion
// FIXES: Replaced insecure fastReader() (math/rand with timestamp seed) with crypto/rand. Replaced classical RSA-2048 and classical ECDH P-256 with NIST Post-Quantum Cryptography standards: ML-DSA-65 (FIPS 204) for signing and ML-KEM-768 (FIPS 203) for key encapsulation.
func NewKeys() (Keys, error) {
	dsaKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return Keys{}, err
	}
	kemKey, err := mlkem.GenerateKey768()
	if err != nil {
		return Keys{}, err
	}
	der := pem.EncodeToMemory(&pem.Block{
		Type:  "ML-DSA PRIVATE KEY",
		Bytes: dsaKey.Bytes(),
	})
	return Keys{
		RSAPrivate: string(der),
		ECCPrivate: kemKey.Bytes(),
		dsaKey:     dsaKey,
		kemKey:     kemKey,
	}, nil
}

// Load parses the stored private keys
func (k *Keys) Load() (err error) {
	block, _ := pem.Decode([]byte(k.RSAPrivate))
	if block == nil {
		return errors.New("no signing key found")
	}
	if k.dsaKey, err = mldsa.NewPrivateKey(mldsa.MLDSA65(), block.Bytes); err != nil {
		return err
	}
	k.kemKey, err = mlkem.NewDecapsulationKey768(k.ECCPrivate)
	return err
}

// PublicKeys returns the public halves: ML-DSA-65 public key and ML-KEM-768 encapsulation key
func (k *Keys) PublicKeys() (rsaDER, eccRaw []byte) {
	return k.dsaKey.PublicKey().Bytes(), k.kemKey.EncapsulationKey().Bytes()
}

// Fingerprint is a short hash of public key material, for people to compare
func Fingerprint(parts ...[]byte) string {
	sum := sha256.Sum256(bytes.Join(parts, nil))
	return hex.EncodeToString(sum[:12])
}

// CBOMs: no
// FIXES: Replaced insecure fastReader() (math/rand) with crypto/rand.Reader to generate cryptographically secure random salts.
func NewSalt() []byte {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		panic(err)
	}
	return salt
}

// DeriveKey turns a password into a 256-bit file key
func DeriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 2, 64*1024, 1, keyLen)
}

// CBOMs: yes
// cdxgen
// CBOMkit-hyperion
// FIXES: Replaced insecure AES ECB mode (raw blocks) and manual PKCS#7 padding with authenticated encryption using AES-256-GCM (cipher.NewGCM) and a fresh 12-byte random nonce prepended to each ciphertext, providing semantic security, confidentiality, and integrity.
func Encrypt(key, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plain, nil), nil
}

func Decrypt(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(data) < gcm.NonceSize()+gcm.Overhead() {
		return nil, errors.New("invalid ciphertext length")
	}
	nonce := data[:gcm.NonceSize()]
	ciphertext := data[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// CBOMs: yes
// cdxgen
// CBOMkit-hyperion
// FIXES: Replaced cryptographically broken MD5 hash with collision-resistant SHA-256 (sha256.Sum256).
func Checksum(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// CBOMs: no
// FIXES: Replaced classical ECDH P-256 key agreement and ad-hoc SHA-256 KDF with quantum-resistant ML-KEM-768 (FIPS 203) key encapsulation and AES-256-GCM key wrapping.
func WrapKey(recipientECC, fileKey []byte) (ephemeral, wrapped []byte, err error) {
	ek, err := mlkem.NewEncapsulationKey768(recipientECC)
	if err != nil {
		return nil, nil, err
	}
	sharedKey, ciphertext := ek.Encapsulate()
	wrapped, err = Encrypt(sharedKey, fileKey)
	if err != nil {
		return nil, nil, err
	}
	return ciphertext, wrapped, nil
}

func (k *Keys) UnwrapKey(ephemeral, wrapped []byte) ([]byte, error) {
	if k.kemKey == nil {
		return nil, errors.New("decapsulation key not loaded")
	}
	sharedKey, err := k.kemKey.Decapsulate(ephemeral)
	if err != nil {
		return nil, err
	}
	key, err := Decrypt(sharedKey, wrapped)
	if err == nil && len(key) != keyLen {
		err = errors.New("unexpected key length")
	}
	return key, err
}

// CBOMs: yes
// cdxgen
// CBOMkit-hyperion
// FIXES: Replaced broken MD5 hashing, legacy PKCS#1 v1.5 padding, and non-post-quantum RSA-2048 with NIST Post-Quantum ML-DSA-65 (FIPS 204) digital signatures.
func (k *Keys) Sign(data []byte) ([]byte, error) {
	if k.dsaKey == nil {
		return nil, errors.New("signing key not loaded")
	}
	return k.dsaKey.Sign(rand.Reader, data, nil)
}

func Verify(rsaPublicDER, data, sig []byte) error {
	pub, err := mldsa.NewPublicKey(mldsa.MLDSA65(), rsaPublicDER)
	if err != nil {
		return err
	}
	return mldsa.Verify(pub, data, sig, nil)
}
