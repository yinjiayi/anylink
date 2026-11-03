package sso

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"
)

const (
	browserVectorToken      = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	browserVectorClientSPKI = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9Q=="
	browserVectorEnvelope   = "AAEAAQBbMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfPJ7GI0DT36KUjgDBLUaw8CJaeJ38hs1pgtI/EdmmXgHd1UQ247QQCk9msafdDDbun2t5jzpgimeBLedInhz0QACAAxFqdE4ttEQFY6ZKmYAAwBAeB6N5Q3cmr7UiIW8c/MGhXssDNc03bmqYjRg26sZ00Q5lS0ATn7+7RNP8GcHlMI8AZpGGcHSmBWRWEb5zhuFbgAEAAwAAQIDBAUGBwgJCgs="
)

func browserTestKey(t *testing.T, scalar byte) *ecdh.PrivateKey {
	t.Helper()
	value := make([]byte, 32)
	value[31] = scalar
	key, err := ecdh.P256().NewPrivateKey(value)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func browserTestSPKI(t *testing.T, key any) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func TestParseSTRAPKey(t *testing.T) {
	key, err := ParseSTRAPKey(browserVectorClientSPKI)
	if err != nil {
		t.Fatal(err)
	}
	if !key.Equal(browserTestKey(t, 1).PublicKey()) {
		t.Fatal("decoded STRAP key differs from the independently generated fixture")
	}

	x, y := elliptic.P384().ScalarBaseMult([]byte{1})
	x25519, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := base64.StdEncoding.DecodeString(browserVectorClientSPKI)
	if err != nil {
		t.Fatal(err)
	}
	badPoint := append([]byte(nil), der...)
	clear(badPoint[len(badPoint)-64:])
	nonCanonical := browserVectorClientSPKI[:len(browserVectorClientSPKI)-3] + "R=="
	for name, encoded := range map[string]string{
		"empty":               "",
		"oversized":           strings.Repeat("A", maxSTRAPKeyLength+1),
		"not-base64":          "this is not a base64 key",
		"newline":             browserVectorClientSPKI[:20] + "\n" + browserVectorClientSPKI[20:],
		"leading-space":       " " + browserVectorClientSPKI,
		"truncated":           browserVectorClientSPKI[:40],
		"trailing-DER":        base64.StdEncoding.EncodeToString(append(append([]byte(nil), der...), 0)),
		"noncanonical-base64": nonCanonical,
		"invalid-curve-point": base64.StdEncoding.EncodeToString(badPoint),
		"P384":                browserTestSPKI(t, &ecdsa.PublicKey{Curve: elliptic.P384(), X: x, Y: y}),
		"X25519":              browserTestSPKI(t, x25519.PublicKey()),
		"RSA":                 browserTestSPKI(t, &rsa.PublicKey{N: big.NewInt(3233), E: 17}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseSTRAPKey(encoded); err == nil {
				t.Fatal("accepted invalid STRAP public key")
			}
		})
	}
}

func TestBrowserTokenFixedInteroperabilityVector(t *testing.T) {
	// Generated independently with Python cryptography 50.0.2:
	// ec.derive_private_key(1, SECP256R1()) is the recipient; scalar 2 is
	// the sender; nonce is bytes(range(12)); HKDF(SHA256, 32, None,
	// b"AC_ECIES"); AES-GCM tag is truncated to 12 bytes. Envelope fields
	// are struct.pack('!HH', tag, len(value)) after the version word 1.
	// These public test scalars MUST NOT be used for production encryption.
	nonce := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	encoded, err := sealBrowserToken(browserTestKey(t, 1).PublicKey(), browserVectorToken, browserTestKey(t, 2), nonce)
	if err != nil {
		t.Fatal(err)
	}
	if encoded != browserVectorEnvelope {
		t.Fatalf("wire-format mismatch with independent vector:\n got %s\nwant %s", encoded, browserVectorEnvelope)
	}
	plaintext, err := decryptBrowserEnvelope(browserTestKey(t, 1), browserVectorEnvelope)
	if err != nil || plaintext != browserVectorToken {
		t.Fatalf("independent vector did not decrypt: plaintext %q, error %v", plaintext, err)
	}
	fields, err := parseBrowserEnvelope(browserVectorEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(fields[2]); got != "45a9d138b6d110158e992a66" {
		t.Fatalf("AEAD tag mismatch: %s", got)
	}
}

func TestEncryptBrowserTokenInteroperability(t *testing.T) {
	client := browserTestKey(t, 3)
	first, err := EncryptBrowserToken(client.PublicKey(), browserVectorToken)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := parseBrowserEnvelope(first)
	if err != nil {
		t.Fatal(err)
	}
	if len(fields[1]) != 91 || len(fields[2]) != 12 || len(fields[3]) != len(browserVectorToken) || len(fields[4]) != 12 {
		t.Fatalf("wrong wire field lengths: %d, %d, %d, %d", len(fields[1]), len(fields[2]), len(fields[3]), len(fields[4]))
	}
	plaintext, err := decryptBrowserEnvelope(client, first)
	if err != nil || plaintext != browserVectorToken {
		t.Fatalf("client-side decryption failed: plaintext %q, error %v", plaintext, err)
	}
	second, err := EncryptBrowserToken(client.PublicKey(), browserVectorToken)
	if err != nil {
		t.Fatal(err)
	}
	secondFields, err := parseBrowserEnvelope(second)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(fields[1], secondFields[1]) || bytes.Equal(fields[4], secondFields[4]) {
		t.Fatal("encryption reused its ephemeral key or nonce")
	}
	if _, err := decryptBrowserEnvelope(browserTestKey(t, 4), first); err == nil {
		t.Fatal("another VPN client's key decrypted the ticket")
	}
}

func TestBrowserTokenTampering(t *testing.T) {
	original, err := base64.StdEncoding.DecodeString(browserVectorEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	// Flip each of the four fields in a valid captured envelope. Neither a
	// substituted server key, modified ciphertext, tag nor IV may authenticate.
	offset := 2
	for tag := 1; tag <= 4; tag++ {
		length := int(binary.BigEndian.Uint16(original[offset+2:]))
		modified := append([]byte(nil), original...)
		modified[offset+4+length-1] ^= 1
		if _, err := decryptBrowserEnvelope(browserTestKey(t, 1), base64.StdEncoding.EncodeToString(modified)); err == nil {
			t.Fatalf("tampered field %d authenticated", tag)
		}
		offset += 4 + length
	}
	wrongVersion := append([]byte(nil), original...)
	wrongVersion[1] = 2
	badLength := append([]byte(nil), original...)
	badLength[4], badLength[5] = 255, 255
	for _, malformed := range [][]byte{original[:len(original)-1], wrongVersion, badLength, append(append([]byte(nil), original...), 0)} {
		if _, err := decryptBrowserEnvelope(browserTestKey(t, 1), base64.StdEncoding.EncodeToString(malformed)); err == nil {
			t.Fatal("malformed envelope was accepted by the independent decoder")
		}
	}
}

func TestEncryptBrowserTokenRejectsInvalidInput(t *testing.T) {
	client := browserTestKey(t, 1)
	for _, token := range []string{"", strings.Repeat("a", 15), strings.Repeat("a", 257), "0123456789abcdef-", "0123456789abcdef_", "0123456789abcdef/", "0123456789abcdef\x00", "0123456789abcdef汉"} {
		if _, err := EncryptBrowserToken(client.PublicKey(), token); err == nil {
			t.Fatalf("accepted invalid token %q", token)
		}
	}
	if _, err := EncryptBrowserToken(nil, browserVectorToken); err == nil {
		t.Fatal("accepted nil public key")
	}
	p384, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EncryptBrowserToken(p384.PublicKey(), browserVectorToken); err == nil {
		t.Fatal("accepted P-384 public key")
	}
	for _, token := range []string{strings.Repeat("a", 16), strings.Repeat("Z9", 128)} {
		encoded, err := EncryptBrowserToken(client.PublicKey(), token)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := decryptBrowserEnvelope(client, encoded); err != nil || got != token {
			t.Fatalf("boundary-length ticket failed: %v", err)
		}
	}
}

// Independent client-side decoder: do not use production helpers/constants or
// x/crypto/hkdf. It mirrors the documented OpenConnect receiver contract and
// implements RFC 5869's single SHA-256 output block directly with HMAC.
func parseBrowserEnvelope(encoded string) (map[uint16][]byte, error) {
	payload, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(payload) < 2 || binary.BigEndian.Uint16(payload) != 1 {
		return nil, errors.New("invalid envelope version or encoding")
	}
	payload = payload[2:]
	fields := make(map[uint16][]byte)
	for expected := uint16(1); expected <= 4; expected++ {
		if len(payload) < 4 {
			return nil, errors.New("truncated envelope")
		}
		tag, length := binary.BigEndian.Uint16(payload), int(binary.BigEndian.Uint16(payload[2:]))
		if tag != expected || length > len(payload)-4 {
			return nil, errors.New("invalid TLV order or length")
		}
		fields[tag] = payload[4 : 4+length]
		payload = payload[4+length:]
	}
	if len(payload) != 0 || len(fields[2]) != 12 || len(fields[4]) != 12 {
		return nil, errors.New("invalid envelope lengths")
	}
	return fields, nil
}

func decryptBrowserEnvelope(client *ecdh.PrivateKey, encoded string) (string, error) {
	fields, err := parseBrowserEnvelope(encoded)
	if err != nil {
		return "", err
	}
	parsed, err := x509.ParsePKIXPublicKey(fields[1])
	if err != nil {
		return "", err
	}
	ecdsaKey, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return "", errors.New("wrong server public key type")
	}
	server, err := ecdsaKey.ECDH()
	if err != nil {
		return "", err
	}
	shared, err := client.ECDH(server)
	if err != nil {
		return "", err
	}
	extract := hmac.New(sha256.New, make([]byte, 32))
	extract.Write(shared)
	expand := hmac.New(sha256.New, extract.Sum(nil))
	expand.Write([]byte("AC_ECIES"))
	expand.Write([]byte{1})
	block, err := aes.NewCipher(expand.Sum(nil))
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCMWithTagSize(block, 12)
	if err != nil {
		return "", err
	}
	sealed := append(append([]byte(nil), fields[3]...), fields[2]...)
	plaintext, err := aead.Open(nil, fields[4], sealed, nil)
	return string(plaintext), err
}
