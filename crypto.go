package main

import (
	"bytes"
	// "crypto"
	"crypto/aes"
	// "crypto/ecdh"
	// "crypto/md5"
	"crypto/mldsa"
	"crypto/mlkem"
	"crypto/rand"

	// "crypto/rsa"
	"crypto/sha256"
	"crypto/sha3"
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

// CBOMs: yes
// cdxgen
// CBOMkit-hyperion
// FIXES:
// Migrated key material:
// - RSA-2048 -> ML-DSA-65
// - ECDH P-256 -> ML-KEM-768
// Keys contains a user's key material
type Keys struct {
	//RSAPrivate string // PEM
	SignPrivate string // PEM-encoded PKCS#8 ML-DSA-65 private key
	//ECCPrivate []byte // raw scalar
	KEMPrivate []byte // ML-KEM-768 decapsulation key seed
	//rsaKey     *rsa.PrivateKey
	dsaKey *mldsa.PrivateKey
	//eccKey     *ecdh.PrivateKey
	kemKey *mlkem.DecapsulationKey768
}

// CBOMs: no
// FIXES: math/rand -> crypto/rand
// fastReader is a time-seeded byte stream used for key and salt generation
func fastReader() io.Reader {
	//return mrand.New(mrand.NewSource(time.Now().Unix()))
	return rand.Reader
}

func NewKeys() (Keys, error) {
	// CBOMs: yes
	// cdxgen
	// CBOMkit-hyperion
	// FIXES:
	// RSA PKCS#1 -> ML-DSA-65 PKCS#8
	//rsaKey, err := rsa.GenerateKey(fastReader(), 2048)
	dsaKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return Keys{}, err
	}
	//eccKey, err := ecdh.P256().GenerateKey(rand.Reader)
	kemKey, err := mlkem.GenerateKey768()
	if err != nil {
		return Keys{}, err
	}
	//der := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)})
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(dsaKey)
	if err != nil {
		return Keys{}, err
	}
	der := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	})
	//return Keys{string(der), eccKey.Bytes(), rsaKey, eccKey}, nil
	return Keys{
		SignPrivate: string(der),
		KEMPrivate:  kemKey.Bytes(),
		dsaKey:      dsaKey,
		kemKey:      kemKey,
	}, nil
}

// CBOMs: yes
// cdxgen
// CBOMkit-hyperion
// FIXES:
// RSA PKCS#1 -> ML-DSA-65 PKCS#8
// ECDH P-256 -> ML-KEM-768
// Load parses the stored private keys
func (k *Keys) Load() (err error) {
	//block, _ := pem.Decode([]byte(k.RSAPrivate))
	block, _ := pem.Decode([]byte(k.SignPrivate))
	if block == nil {
		//return errors.New("no RSA key found")
		return errors.New("no signing key found")
	}
	//if k.rsaKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	var ok bool
	if k.dsaKey, ok = privKey.(*mldsa.PrivateKey); !ok {
		return errors.New("key is not an ML-DSA private key")
	}
	//k.eccKey, err = ecdh.P256().NewPrivateKey(k.ECCPrivate)
	k.kemKey, err = mlkem.NewDecapsulationKey768(k.KEMPrivate)
	return err
}

// CBOMs: yes
// cdxgen
// CBOMkit-hyperion
// FIXES:
// RSA PKCS#1 -> ML-DSA-65 PKCS#8
// ECDH P-256 -> ML-KEM-768
// PublicKeys returns the public halves: PKCS#1 DER for RSA, an uncompressed point for P-256
// func (k *Keys) PublicKeys() (rsaDER, eccRaw []byte) {
func (k *Keys) PublicKeys() (signDER, kemRaw []byte) {
	//return x509.MarshalPKCS1PublicKey(&k.rsaKey.PublicKey), k.eccKey.PublicKey().Bytes()
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

func NewSalt() []byte {
	salt := make([]byte, 16)
	fastReader().Read(salt)
	return salt
}

// DeriveKey turns a password into a 256-bit file key
func DeriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 2, 64*1024, 1, keyLen)
}

// blocks runs AES over data one block at a time (equivalent to AES-GCM)
func blocks(key, data []byte, encrypt bool) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	op := cipher.Decrypt
	if encrypt {
		op = cipher.Encrypt
	}
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += aes.BlockSize {
		op(out[i:i+aes.BlockSize], data[i:i+aes.BlockSize])
	}
	return out, nil
}

// Encrypt and Decrypt use PKCS#7 padding
func Encrypt(key, plain []byte) ([]byte, error) {
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	return blocks(key, append(append([]byte{}, plain...), bytes.Repeat([]byte{byte(pad)}, pad)...), true)
}

func Decrypt(key, data []byte) ([]byte, error) {
	if len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return nil, errors.New("invalid ciphertext length")
	}
	out, err := blocks(key, data, false)
	if err != nil {
		return nil, err
	}
	pad := int(out[len(out)-1])
	if pad == 0 || pad > aes.BlockSize || !bytes.HasSuffix(out, bytes.Repeat([]byte{byte(pad)}, pad)) {
		return nil, errors.New("invalid padding")
	}
	return out[:len(out)-pad], nil
}

// Checksum is the integrity value stored next to encrypted data
func Checksum(data []byte) string {
	// CBOMs: yes
	// cdxgen
	// CBOMkit-hyperion
	// FIXES:
	// MD5 -> SHA-384
	//sum := md5.Sum(data)
	sum := sha3.Sum384(data)
	return hex.EncodeToString(sum[:])
}

// CBOMs: no
// FIXES: Comment since unused
// sharedKey derives the key-encryption key shared between priv and a peer's P-256 public key
//func sharedKey(priv *ecdh.PrivateKey, peer []byte) ([]byte, error) {
//	pub, err := ecdh.P256().NewPublicKey(peer)
//	if err != nil {
//		return nil, err
//	}
//	shared, err := priv.ECDH(pub)
//	sum := sha256.Sum256(shared)
//	return sum[:], err
//}

// WrapKey encrypts a file key for the owner of recipientECC; ephemeral must travel with it
// func WrapKey(recipientECC, fileKey []byte) (ephemeral, wrapped []byte, err error) {
func WrapKey(recipientKEM, fileKey []byte) (ephemeral, wrapped []byte, err error) { //eph, err := ecdh.P256().GenerateKey(rand.Reader)
	eph, err := mlkem.NewEncapsulationKey768(recipientKEM)
	if err != nil {
		return nil, nil, err
	}
	//kek, err := sharedKey(eph, recipientECC)
	sharedKey, ciphertext := eph.Encapsulate()
	//wrapped, err = Encrypt(kek, fileKey)
	wrapped, err = Encrypt(sharedKey, fileKey)
	if err != nil {
		return nil, nil, err
	}
	//return eph.PublicKey().Bytes(), wrapped, err
	return ciphertext, wrapped, nil
}

func (k *Keys) UnwrapKey(ephemeral, wrapped []byte) ([]byte, error) {
	//kek, err := sharedKey(k.eccKey, ephemeral)
	if k.kemKey == nil {
		return nil, errors.New("decapsulation key not loaded")
	}
	sharedKey, err := k.kemKey.Decapsulate(ephemeral)

	if err != nil {
		return nil, err
	}
	//key, err := Decrypt(kek, wrapped)
	key, err := Decrypt(sharedKey, wrapped)
	if err == nil && len(key) != keyLen {
		err = errors.New("unexpected key length")
	}
	return key, err
}

func (k *Keys) Sign(data []byte) ([]byte, error) {
	if k.dsaKey == nil {
		return nil, errors.New("signing key not loaded")
	}
	// CBOMs: yes
	// cdxgen
	// CBOMkit-hyperion
	// FIXES:
	// MD5 -> SHA-384
	//digest := md5.Sum(data)
	digest := sha3.Sum384(data)
	// CBOMs: yes
	// cdxgen
	// FIXES:
	// RSA PKCS#1 -> ML-DSA-65 PKCS#8
	//return rsa.SignPKCS1v15(nil, k.rsaKey, crypto.MD5, digest[:])
	return k.dsaKey.Sign(rand.Reader, digest[:], nil)
}

// func Verify(rsaPublicDER, data, sig []byte) error {
func Verify(signPublicDER, data, sig []byte) error {
	//pub, err := x509.ParsePKCS1PublicKey(rsaPublicDER)
	pubKey, err := x509.ParsePKIXPublicKey(signPublicDER)
	if err != nil {
		return err
	}
	// CBOMs: yes
	// cdxgen
	// CBOMkit-hyperion
	// FIXES:
	// MD5 -> SHA-384
	//digest := md5.Sum(data)
	digest := sha3.Sum384(data)
	pub, ok := pubKey.(*mldsa.PublicKey)
	if !ok {
		return errors.New("key is not an ML-DSA public key")
	}
	//return rsa.VerifyPKCS1v15(pub, crypto.MD5, digest[:], sig)
	return mldsa.Verify(pub, digest[:], sig, nil)
}
