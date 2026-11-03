package sso

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/hkdf"
)

const (
	maxSTRAPKeyLength     = 256
	minBrowserTokenLength = 16
	maxBrowserTokenLength = 256
	browserNonceSize      = 12
	browserTagSize        = 12
)

// ParseSTRAPKey reads the X-AnyConnect-STRAP-DH-Pubkey header: standard
// Base64-encoded DER SubjectPublicKeyInfo containing a P-256 public key.
// Bound the header before decoding and reject all other key types and curves.
func ParseSTRAPKey(encoded string) (*ecdh.PublicKey, error) {
	if len(encoded) == 0 || len(encoded) > maxSTRAPKeyLength || strings.ContainsAny(encoded, " \t\r\n") {
		return nil, errors.New("invalid STRAP DH public key encoding")
	}
	der, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return nil, errors.New("invalid STRAP DH public key encoding")
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, errors.New("invalid STRAP DH public key")
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("STRAP DH public key must use P-256")
	}
	publicKey, err := key.ECDH()
	if err != nil || publicKey.Curve() != ecdh.P256() {
		return nil, errors.New("STRAP DH public key must use P-256")
	}
	return publicKey, nil
}

// EncryptBrowserToken returns the standard Base64 Cisco external-browser SSO
// envelope. The caller URL-escapes it for /api/sso/<envelope> on localhost:29786.
// token is a short-lived, single-use VPN ticket, not an OAuth access/ID token.
// The client accepts ASCII alphanumeric tickets; use cryptographically random
// hex tickets (for example, 32 random bytes encoded as 64 hex characters).
//
// Cisco's format is custom ECIES, not the RFC 9180 HPKE wire format. Its
// parameters and TLVs are documented by OpenConnect's hpke.c and openssl.c:
// https://gitlab.com/openconnect/openconnect/-/tree/70d1e79d1e55849dfc71dcc199b1edb535b547e4
func EncryptBrowserToken(publicKey *ecdh.PublicKey, token string) (string, error) {
	if err := validateBrowserToken(publicKey, token); err != nil {
		return "", err
	}
	ephemeralKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate browser SSO key: %w", err)
	}
	nonce := make([]byte, browserNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate browser SSO nonce: %w", err)
	}
	return sealBrowserToken(publicKey, token, ephemeralKey, nonce)
}

func validateBrowserToken(publicKey *ecdh.PublicKey, token string) error {
	if publicKey == nil || publicKey.Curve() != ecdh.P256() {
		return errors.New("browser SSO public key must use P-256")
	}
	if len(token) < minBrowserTokenLength || len(token) > maxBrowserTokenLength {
		return errors.New("browser SSO ticket length must be between 16 and 256 bytes")
	}
	for i := 0; i < len(token); i++ {
		c := token[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return errors.New("browser SSO ticket must be ASCII alphanumeric")
		}
	}
	return nil
}

// Keeping the deterministic sealing step separate permits comparison with an
// independently generated protocol vector without changing production entropy.
func sealBrowserToken(publicKey *ecdh.PublicKey, token string, ephemeralKey *ecdh.PrivateKey, nonce []byte) (string, error) {
	if err := validateBrowserToken(publicKey, token); err != nil {
		return "", err
	}
	if ephemeralKey == nil || ephemeralKey.Curve() != ecdh.P256() || len(nonce) != browserNonceSize {
		return "", errors.New("invalid browser SSO encryption parameters")
	}
	shared, err := ephemeralKey.ECDH(publicKey)
	if err != nil {
		return "", fmt.Errorf("derive browser SSO key: %w", err)
	}
	defer clear(shared)
	key := make([]byte, 32)
	defer clear(key)
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, nil, []byte("AC_ECIES")), key); err != nil {
		return "", fmt.Errorf("derive browser SSO encryption key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("initialize browser SSO cipher: %w", err)
	}
	aead, err := cipher.NewGCMWithTagSize(block, browserTagSize)
	if err != nil {
		return "", fmt.Errorf("initialize browser SSO AEAD: %w", err)
	}
	sealed := aead.Seal(nil, nonce, []byte(token), nil)
	ciphertext := sealed[:len(sealed)-browserTagSize]
	tag := sealed[len(sealed)-browserTagSize:]
	der, err := x509.MarshalPKIXPublicKey(ephemeralKey.PublicKey())
	if err != nil {
		return "", fmt.Errorf("encode browser SSO public key: %w", err)
	}

	envelope := []byte{0, 1} // Cisco envelope version, followed by four TLVs.
	for _, field := range []struct {
		tag   uint16
		value []byte
	}{
		{1, der},
		{2, tag},
		{3, ciphertext},
		{4, nonce},
	} {
		envelope = binary.BigEndian.AppendUint16(envelope, field.tag)
		envelope = binary.BigEndian.AppendUint16(envelope, uint16(len(field.value)))
		envelope = append(envelope, field.value...)
	}
	return base64.StdEncoding.EncodeToString(envelope), nil
}
