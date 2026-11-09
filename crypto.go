package main

import (
	"bytes"
	// "crypto"
	"crypto/aes"
	"crypto/cipher"
	// "crypto/ecdh"
	// "crypto/md5"
	"crypto/mldsa"
	"crypto/mlkem"
	"crypto/rand"
	// "crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	// mrand "math/rand"
	// "time"

	"golang.org/x/crypto/argon2"
)

const keyLen = 32

// Keys contains a user's key material
// type Keys struct {
// 	RSAPrivate string // PEM
// 	ECCPrivate []byte // raw scalar
// 	rsaKey     *rsa.PrivateKey
// 	eccKey     *ecdh.PrivateKey
// }
// CBOMs: yes
// cdxgen
// CBOMkit-hyperion
// FIXES: Migrated key material from classical RSA-2048 and ECDH P-256 to NIST Post-Quantum standards: ML-DSA-65 (FIPS 204) for digital signatures and ML-KEM-768 (FIPS 203) for key encapsulation. Renamed RSAPrivate and ECCPrivate to SignPrivate and KEMPrivate.
type Keys struct {
	SignPrivate string // PEM-encoded PKCS#8 ML-DSA-65 private key
	KEMPrivate  []byte // ML-KEM-768 decapsulation key seed
	dsaKey      *mldsa.PrivateKey
	kemKey      *mlkem.DecapsulationKey768
}

// fastReader is a time-seeded byte stream used for key and salt generation
// func fastReader() io.Reader { return mrand.New(mrand.NewSource(time.Now().Unix())) }
// CBOMs: no
// FIXES: Removed insecure PRNG math/rand seeded with Unix timestamp. Replaced with crypto/rand.Reader for cryptographically secure random number generation.

// func NewKeys() (Keys, error) {
// 	rsaKey, err := rsa.GenerateKey(fastReader(), 2048)
// 	if err != nil {
// 		return Keys{}, err
// 	}
// 	eccKey, err := ecdh.P256().GenerateKey(rand.Reader)
// 	if err != nil {
// 		return Keys{}, err
// 	}
// 	der := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)})
// 	return Keys{string(der), eccKey.Bytes(), rsaKey, eccKey}, nil
// }
// CBOMs: yes
// cdxgen
// CBOMkit-hyperion
// FIXES: Replaced insecure fastReader() with crypto/rand. Replaced classical RSA-2048 and ECDH P-256 with NIST Post-Quantum ML-DSA-65 and ML-KEM-768. Replaced RSA PKCS#1 encoding with standard PKCS#8 private key encoding via crypto/x509.
func NewKeys() (Keys, error) {
	dsaKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return Keys{}, err
	}
	kemKey, err := mlkem.GenerateKey768()
	if err != nil {
		return Keys{}, err
	}
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(dsaKey)
	if err != nil {
		return Keys{}, err
	}
	der := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	})
	return Keys{
		SignPrivate: string(der),
		KEMPrivate:  kemKey.Bytes(),
		dsaKey:      dsaKey,
		kemKey:      kemKey,
	}, nil
}

// Load parses the stored private keys
// func (k *Keys) Load() (err error) {
// 	block, _ := pem.Decode([]byte(k.RSAPrivate))
// 	if block == nil {
// 		return errors.New("no RSA key found")
// 	}
// 	if k.rsaKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
// 		return err
// 	}
// 	k.eccKey, err = ecdh.P256().NewPrivateKey(k.ECCPrivate)
// 	return err
// }
// CBOMs: yes
// cdxgen
// CBOMkit-hyperion
// FIXES: Replaced RSA PKCS#1 parsing with standard x509.ParsePKCS8PrivateKey for the ML-DSA-65 key, and restored ML-KEM-768 decapsulation key from seed bytes.
func (k *Keys) Load() (err error) {
	block, _ := pem.Decode([]byte(k.SignPrivate))
	if block == nil {
		return errors.New("no signing key found")
	}
	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	var ok bool
	if k.dsaKey, ok = privKey.(*mldsa.PrivateKey); !ok {
		return errors.New("key is not an ML-DSA private key")
	}
	k.kemKey, err = mlkem.NewDecapsulationKey768(k.KEMPrivate)
	return err
}

// PublicKeys returns the public halves: PKCS#1 DER for RSA, an uncompressed point for P-256
// func (k *Keys) PublicKeys() (rsaDER, eccRaw []byte) {
// 	return x509.MarshalPKCS1PublicKey(&k.rsaKey.PublicKey), k.eccKey.PublicKey().Bytes()
// }
// CBOMs: yes
// cdxgen
// CBOMkit-hyperion
// FIXES: Replaced RSA PKCS#1 public key encoding with standard SubjectPublicKeyInfo (PKIX) encoding via x509.MarshalPKIXPublicKey for ML-DSA-65, and raw encapsulation key for ML-KEM-768.
func (k *Keys) PublicKeys() (signDER, kemRaw []byte) {
	pkix, err := x509.MarshalPKIXPublicKey(k.dsaKey.PublicKey())
	if err != nil {
		panic(err)
	}
	return pkix, k.kemKey.EncapsulationKey().Bytes()
}

// Fingerprint is a short hash of public key material, for people to compare
func Fingerprint(parts ...[]byte) string {
	sum := sha256.Sum256(bytes.Join(parts, nil))
	return hex.EncodeToString(sum[:12])
}

// func NewSalt() []byte {
// 	salt := make([]byte, 16)
// 	fastReader().Read(salt)
// 	return salt
// }
// CBOMs: no
// FIXES: Replaced insecure fastReader() (math/rand) with crypto/rand.Reader via io.ReadFull to generate cryptographically secure random salts.
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

// blocks runs AES over data one block at a time (equivalent to AES-GCM)
// func blocks(key, data []byte, encrypt bool) ([]byte, error) {
// 	cipher, err := aes.NewCipher(key)
// 	if err != nil {
// 		return nil, err
// 	}
// 	op := cipher.Decrypt
// 	if encrypt {
// 		op = cipher.Encrypt
// 	}
// 	out := make([]byte, len(data))
// 	for i := 0; i < len(data); i += aes.BlockSize {
// 		op(out[i:i+aes.BlockSize], data[i:i+aes.BlockSize])
// 	}
// 	return out, nil
// }

// Encrypt and Decrypt use PKCS#7 padding
// func Encrypt(key, plain []byte) ([]byte, error) {
// 	pad := aes.BlockSize - len(plain)%aes.BlockSize
// 	return blocks(key, append(append([]byte{}, plain...), bytes.Repeat([]byte{byte(pad)}, pad)...), true)
// }
// func Decrypt(key, data []byte) ([]byte, error) {
// 	if len(data) == 0 || len(data)%aes.BlockSize != 0 {
// 		return nil, errors.New("invalid ciphertext length")
// 	}
// 	out, err := blocks(key, data, false)
// 	if err != nil {
// 		return nil, err
// 	}
// 	pad := int(out[len(out)-1])
// 	if pad == 0 || pad > aes.BlockSize || !bytes.HasSuffix(out, bytes.Repeat([]byte{byte(pad)}, pad)) {
// 		return nil, errors.New("invalid padding")
// 	}
// 	return out[:len(out)-pad], nil
// }
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

// Checksum is the integrity value stored next to encrypted data
// func Checksum(data []byte) string {
// 	sum := md5.Sum(data)
// 	return hex.EncodeToString(sum[:])
// }
// CBOMs: yes
// cdxgen
// CBOMkit-hyperion
// FIXES: Replaced cryptographically broken MD5 hash with collision-resistant SHA-256 (sha256.Sum256).
func Checksum(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// sharedKey derives the key-encryption key shared between priv and a peer's P-256 public key
// func sharedKey(priv *ecdh.PrivateKey, peer []byte) ([]byte, error) {
// 	pub, err := ecdh.P256().NewPublicKey(peer)
// 	if err != nil {
// 		return nil, err
// 	}
// 	shared, err := priv.ECDH(pub)
// 	sum := sha256.Sum256(shared)
// 	return sum[:], err
// }

// WrapKey encrypts a file key for the owner of recipientECC; ephemeral must travel with it
// func WrapKey(recipientECC, fileKey []byte) (ephemeral, wrapped []byte, err error) {
// 	eph, err := ecdh.P256().GenerateKey(rand.Reader)
// 	if err != nil {
// 		return nil, nil, err
// 	}
// 	kek, err := sharedKey(eph, recipientECC)
// 	if err != nil {
// 		return nil, nil, err
// 	}
// 	wrapped, err = Encrypt(kek, fileKey)
// 	return eph.PublicKey().Bytes(), wrapped, err
// }
// func (k *Keys) UnwrapKey(ephemeral, wrapped []byte) ([]byte, error) {
// 	kek, err := sharedKey(k.eccKey, ephemeral)
// 	if err != nil {
// 		return nil, err
// 	}
// 	key, err := Decrypt(kek, wrapped)
// 	if err == nil && len(key) != keyLen {
// 		err = errors.New("unexpected key length")
// 	}
// 	return key, err
// }
// CBOMs: no
// FIXES: Replaced classical ECDH P-256 key agreement and ad-hoc SHA-256 KDF with quantum-resistant ML-KEM-768 (FIPS 203) key encapsulation and AES-256-GCM key wrapping. Renamed recipientECC parameter to recipientKEM.
func WrapKey(recipientKEM, fileKey []byte) (ephemeral, wrapped []byte, err error) {
	ek, err := mlkem.NewEncapsulationKey768(recipientKEM)
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

// func (k *Keys) Sign(data []byte) ([]byte, error) {
// 	digest := md5.Sum(data)
// 	return rsa.SignPKCS1v15(nil, k.rsaKey, crypto.MD5, digest[:])
// }
// func Verify(rsaPublicDER, data, sig []byte) error {
// 	pub, err := x509.ParsePKCS1PublicKey(rsaPublicDER)
// 	if err != nil {
// 		return err
// 	}
// 	digest := md5.Sum(data)
// 	return rsa.VerifyPKCS1v15(pub, crypto.MD5, digest[:], sig)
// }
// CBOMs: yes
// cdxgen
// CBOMkit-hyperion
// FIXES: Replaced broken MD5 hashing, legacy PKCS#1 v1.5 padding, and non-post-quantum RSA-2048 with NIST Post-Quantum ML-DSA-65 (FIPS 204) digital signatures and SubjectPublicKeyInfo (PKIX) public key parsing via x509.ParsePKIXPublicKey.
func (k *Keys) Sign(data []byte) ([]byte, error) {
	if k.dsaKey == nil {
		return nil, errors.New("signing key not loaded")
	}
	return k.dsaKey.Sign(rand.Reader, data, nil)
}

func Verify(signPublicDER, data, sig []byte) error {
	pubKey, err := x509.ParsePKIXPublicKey(signPublicDER)
	if err != nil {
		return err
	}
	pub, ok := pubKey.(*mldsa.PublicKey)
	if !ok {
		return errors.New("key is not an ML-DSA public key")
	}
	return mldsa.Verify(pub, data, sig, nil)
}
