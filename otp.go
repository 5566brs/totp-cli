package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

var algorithms = map[string]func() hash.Hash{
	"SHA1":   sha1.New,
	"SHA256": sha256.New,
	"SHA512": sha512.New,
}

// normalizeSecret upper-cases a base32 secret and removes the separators and
// padding that services commonly show, then rejects anything else.
func normalizeSecret(secret string) (string, error) {
	s := strings.NewReplacer(" ", "", "-", "", "\t", "", "\r", "", "\n", "").Replace(secret)
	s = strings.TrimRight(strings.ToUpper(s), "=")
	if s == "" {
		return "", errors.New("secret is empty")
	}
	for _, c := range s {
		if !strings.ContainsRune(base32Alphabet, c) {
			return "", fmt.Errorf("secret is not base32: invalid character %q (allowed: A-Z, 2-7)", c)
		}
	}
	return s, nil
}

// decodeSecret decodes a normalized secret per RFC 4648, as authenticator apps
// do: leftover bits at the end are discarded.
func decodeSecret(s string) []byte {
	key, _ := unpackBase32(s)
	return key
}

// decodeSecretITTools reproduces it-tools' base32toHex: leftover bits at the
// end are kept as one extra low-valued byte instead of being discarded.
func decodeSecretITTools(s string) []byte {
	key, leftover := unpackBase32(s)
	if leftover >= 0 {
		key = append(key, byte(leftover))
	}
	return key
}

// unpackBase32 returns the whole bytes of a normalized secret and the value of
// the bits left after them, or -1 if there are none.
func unpackBase32(s string) ([]byte, int) {
	key := make([]byte, 0, len(s)*5/8)
	var acc, bits uint
	for _, c := range s {
		acc = acc<<5 | uint(strings.IndexRune(base32Alphabet, c))
		bits += 5
		if bits >= 8 {
			bits -= 8
			key = append(key, byte(acc>>bits))
			acc &= 1<<bits - 1
		}
	}
	if bits == 0 {
		return key, -1
	}
	return key, int(acc)
}

// hotp implements RFC 4226 (with the RFC 6238 hash extensions).
func hotp(key []byte, counter uint64, digits int, newHash func() hash.Hash) string {
	mac := hmac.New(newHash, key)
	binary.Write(mac, binary.BigEndian, counter)
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	v := uint64(binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff)

	mod := uint64(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, v%mod)
}

func totp(key []byte, t time.Time, period, digits int, newHash func() hash.Hash) string {
	return hotp(key, uint64(t.Unix())/uint64(period), digits, newHash)
}

// remaining returns how many seconds the code for t stays valid.
func remaining(t time.Time, period int) int {
	return period - int(t.Unix()%int64(period))
}

func generateSecret(length int) (string, error) {
	// 32 divides 256, so the modulo is unbiased.
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = base32Alphabet[b[i]%32]
	}
	return string(b), nil
}

// keyURI builds the otpauth:// URI encoded in the QR code, in the same format
// as it-tools' buildKeyUri.
func keyURI(secret, issuer, account, algorithm string, digits, period int) string {
	return "otpauth://totp/" + encodeURIComponent(issuer) + ":" + encodeURIComponent(account) +
		"?issuer=" + encodeURIComponent(issuer) +
		"&secret=" + encodeURIComponent(secret) +
		"&algorithm=" + algorithm +
		"&digits=" + strconv.Itoa(digits) +
		"&period=" + strconv.Itoa(period)
}

func encodeURIComponent(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}
