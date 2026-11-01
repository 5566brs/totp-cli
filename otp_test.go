package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"strings"
	"testing"
	"time"
)

// Vectors below come from it-tools' otp.service.test.ts.
const demoSecret = "JBSWY3DPEHPK3PXP"

func TestHOTPMatchesITTools(t *testing.T) {
	key := decodeSecret(demoSecret)
	for counter, want := range []string{"282760", "996554", "602287", "143627", "960129"} {
		if got := hotp(key, uint64(counter), 6, sha1.New); got != want {
			t.Errorf("counter %d: got %s, want %s", counter, got, want)
		}
	}
}

func TestTOTPMatchesITTools(t *testing.T) {
	key := decodeSecret(demoSecret)
	cases := []struct {
		unix int64
		want string
	}{{0, "282760"}, {1465324707, "341128"}, {1365324707, "089029"}}
	for _, c := range cases {
		if got := totp(key, time.Unix(c.unix, 0), 30, 6, sha1.New); got != c.want {
			t.Errorf("t=%d: got %s, want %s", c.unix, got, c.want)
		}
	}
}

func TestDecodeITToolsVectors(t *testing.T) {
	for in, want := range map[string]string{
		"ABCDEF":   "00443205",
		"7777":     "ffff0f",
		demoSecret: "48656c6c6f21deadbeef",
	} {
		if got := hex.EncodeToString(decodeSecretITTools(in)); got != want {
			t.Errorf("%s: got %s, want %s", in, got, want)
		}
	}
}

func TestDecodeRFC4648DropsLeftoverBits(t *testing.T) {
	for in, want := range map[string]string{
		"7777":      "ffff",
		"MZXW6YQ":   "666f6f62",
		"MZXW6YTB":  "666f6f6261",
		"MZXW6YTBA": "666f6f6261", // 9 characters: non-canonical but accepted
	} {
		if got := hex.EncodeToString(decodeSecret(in)); got != want {
			t.Errorf("%s: got %s, want %s", in, got, want)
		}
	}
}

// RFC 6238 appendix B, 8 digits.
func TestRFC6238(t *testing.T) {
	cases := []struct {
		alg  func() hash.Hash
		key  string
		unix int64
		want string
	}{
		{sha1.New, "12345678901234567890", 59, "94287082"},
		{sha1.New, "12345678901234567890", 1111111109, "07081804"},
		{sha1.New, "12345678901234567890", 20000000000, "65353130"},
		{sha256.New, "12345678901234567890123456789012", 59, "46119246"},
		{sha256.New, "12345678901234567890123456789012", 1234567890, "91819424"},
		{sha512.New, strings.Repeat("1234567890", 6) + "1234", 59, "90693936"},
		{sha512.New, strings.Repeat("1234567890", 6) + "1234", 2000000000, "38618901"},
	}
	for _, c := range cases {
		if got := totp([]byte(c.key), time.Unix(c.unix, 0), 30, 8, c.alg); got != c.want {
			t.Errorf("t=%d: got %s, want %s", c.unix, got, c.want)
		}
	}
}

func TestTenDigitsDoNotOverflow(t *testing.T) {
	if got := totp(decodeSecret(demoSecret), time.Unix(59, 0), 30, 10, sha1.New); len(got) != 10 {
		t.Errorf("got %q", got)
	}
}

func TestNormalizeSecret(t *testing.T) {
	if got, err := normalizeSecret(" jbsw y3dp-ehpk 3pxp==\n"); err != nil || got != demoSecret {
		t.Errorf("got %q, %v", got, err)
	}
	for _, bad := range []string{"", "   ", "ABC1", "ABC!"} {
		if _, err := normalizeSecret(bad); err == nil {
			t.Errorf("%q: expected error", bad)
		}
	}
}

func TestKeyURIMatchesITTools(t *testing.T) {
	want := "otpauth://totp/IT-Tools:demo-user?issuer=IT-Tools&secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30"
	if got := keyURI(demoSecret, "IT-Tools", "demo-user", "SHA1", 6, 30); got != want {
		t.Errorf("got %s", got)
	}
	got := keyURI(demoSecret, "My App", "me@example.com", "SHA1", 6, 30)
	if !strings.HasPrefix(got, "otpauth://totp/My%20App:me%40example.com?issuer=My%20App&") {
		t.Errorf("got %s", got)
	}
}

func TestRunOutput(t *testing.T) {
	var out, errOut strings.Builder
	err := run([]string{"--time", "1465324707", demoSecret, "-p", "30"}, strings.NewReader(""), &out, &errOut)
	if err != nil || out.String() != "341128\n" {
		t.Errorf("out %q, err %v", out.String(), err)
	}
	out.Reset()
	err = run([]string{"-t", "0"}, strings.NewReader(demoSecret+"\n"), &out, &errOut)
	if err != nil || out.String() != "282760\n" {
		t.Errorf("stdin: out %q, err %v", out.String(), err)
	}
}

func TestSecretLengthNote(t *testing.T) {
	var std, compat, errOut strings.Builder
	in := strings.NewReader("")
	if err := run([]string{"-t", "0", "7777"}, in, &std, &errOut); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errOut.String(), "--it-tools") {
		t.Errorf("missing note: %q", errOut.String())
	}
	if err := run([]string{"-t", "0", "--it-tools", "7777"}, in, &compat, &errOut); err != nil {
		t.Fatal(err)
	}
	if std.String() == compat.String() {
		t.Error("--it-tools should change the code for this secret")
	}
}
