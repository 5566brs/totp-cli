// totp generates RFC 6238 one-time codes compatible with it-tools' OTP
// generator and with authenticator apps.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

const usage = `totp - generate time-based one-time passwords (TOTP)

Usage:
  totp [flags] [SECRET]

The base32 secret is taken from, in order: the SECRET argument, the
TOTP_SECRET environment variable, or stdin. Prefer the last two: command-line
arguments end up in shell history and process lists.

Flags may appear before or after SECRET.

Flags:
  -p, --period N      seconds per code (default 30)
  -d, --digits N      code length, 6-10 (default 6)
  -a, --algorithm A   SHA1, SHA256 or SHA512 (default SHA1)
  -t, --time T        generate for this time: Unix seconds or RFC 3339,
                      e.g. 2026-11-01T12:00:00Z (default now)
  -w, --watch         keep printing fresh codes with a countdown; Ctrl+C stops
      --qr            print a QR code to add the secret to an authenticator app
      --invert        swap QR colors, if a phone can't read it
      --uri           print the otpauth:// URI
      --issuer NAME   issuer shown in the app (default IT-Tools)
      --account NAME  account shown in the app (default demo-user)
      --generate      create a new random secret instead of reading one
      --length N      length of a generated secret (default 16)
      --it-tools      decode the secret exactly like it-tools; see README
  -h, --help          show this help

Examples:
  totp JBSWY3DPEHPK3PXP
  totp --time 2026-11-01T12:00:00Z --digits 8 JBSWY3DPEHPK3PXP
  totp --generate --qr --issuer GitHub --account me@example.com
  echo JBSWY3DPEHPK3PXP | totp --watch
`

type options struct {
	period, digits, length       int
	algorithm, timeArg           string
	issuer, account              string
	watch, qr, invert, uri       bool
	generate, itTools, showUsage bool
}

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	opts, positional, err := parseArgs(args)
	if err != nil {
		return err
	}
	if opts.showUsage {
		fmt.Fprint(stdout, usage)
		return nil
	}
	if opts.period < 1 {
		return errors.New("--period must be at least 1")
	}
	if opts.digits < 6 || opts.digits > 10 {
		return errors.New("--digits must be between 6 and 10")
	}
	opts.algorithm = strings.ToUpper(strings.ReplaceAll(opts.algorithm, "-", ""))
	newHash, ok := algorithms[opts.algorithm]
	if !ok {
		return fmt.Errorf("unknown algorithm %q (use SHA1, SHA256 or SHA512)", opts.algorithm)
	}
	if opts.watch && opts.timeArg != "" {
		return errors.New("--watch and --time cannot be combined")
	}
	at := time.Now()
	if opts.timeArg != "" {
		if at, err = parseTime(opts.timeArg); err != nil {
			return err
		}
	}

	secret, err := resolveSecret(opts, positional, stdin, stdout)
	if err != nil {
		return err
	}
	key := decodeSecret(secret)
	compat := decodeSecretITTools(secret)
	if opts.itTools {
		key = compat
	} else if totp(key, at, opts.period, opts.digits, newHash) != totp(compat, at, opts.period, opts.digits, newHash) {
		fmt.Fprintln(stderr, "note: it-tools shows a different code for this secret because its length is not a multiple of 8; pass --it-tools to match it")
	}

	if opts.uri || opts.qr {
		uri := keyURI(secret, opts.issuer, opts.account, opts.algorithm, opts.digits, opts.period)
		if opts.uri {
			fmt.Fprintln(stdout, uri)
		}
		if opts.qr {
			qr, err := renderQR(uri, opts.invert)
			if err != nil {
				return err
			}
			fmt.Fprint(stdout, qr)
		}
	}
	if opts.watch {
		watch(stdout, key, opts, newHash)
		return nil
	}

	fmt.Fprintln(stdout, totp(key, at, opts.period, opts.digits, newHash))
	fmt.Fprintf(stderr, "valid for %ds\n", remaining(at, opts.period))
	return nil
}

// parseArgs parses flags on both sides of the positional secret, which the
// standard flag package alone does not allow.
func parseArgs(args []string) (*options, []string, error) {
	var o options
	fs := flag.NewFlagSet("totp", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.IntVar(&o.period, "period", 30, "")
	fs.IntVar(&o.period, "p", 30, "")
	fs.IntVar(&o.digits, "digits", 6, "")
	fs.IntVar(&o.digits, "d", 6, "")
	fs.StringVar(&o.algorithm, "algorithm", "SHA1", "")
	fs.StringVar(&o.algorithm, "a", "SHA1", "")
	fs.StringVar(&o.timeArg, "time", "", "")
	fs.StringVar(&o.timeArg, "t", "", "")
	fs.BoolVar(&o.watch, "watch", false, "")
	fs.BoolVar(&o.watch, "w", false, "")
	fs.BoolVar(&o.qr, "qr", false, "")
	fs.BoolVar(&o.invert, "invert", false, "")
	fs.BoolVar(&o.uri, "uri", false, "")
	fs.StringVar(&o.issuer, "issuer", "IT-Tools", "")
	fs.StringVar(&o.account, "account", "demo-user", "")
	fs.BoolVar(&o.generate, "generate", false, "")
	fs.IntVar(&o.length, "length", 16, "")
	fs.BoolVar(&o.itTools, "it-tools", false, "")
	fs.BoolVar(&o.showUsage, "help", false, "")
	fs.BoolVar(&o.showUsage, "h", false, "")

	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, nil, fmt.Errorf("%w (see --help)", err)
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
	if len(positional) > 1 {
		return nil, nil, fmt.Errorf("expected one secret, got %d arguments", len(positional))
	}
	return &o, positional, nil
}

func parseTime(s string) (time.Time, error) {
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		if n < 0 {
			return time.Time{}, errors.New("--time must not be before 1970")
		}
		return time.Unix(n, 0), nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid --time %q: use Unix seconds or RFC 3339 (2026-11-01T12:00:00Z)", s)
	}
	if t.Unix() < 0 {
		return time.Time{}, errors.New("--time must not be before 1970")
	}
	return t, nil
}

func resolveSecret(o *options, positional []string, stdin io.Reader, stdout io.Writer) (string, error) {
	if o.generate {
		if len(positional) > 0 {
			return "", errors.New("--generate cannot be combined with a SECRET")
		}
		if o.length < 16 {
			return "", errors.New("--length must be at least 16")
		}
		secret, err := generateSecret(o.length)
		if err != nil {
			return "", err
		}
		fmt.Fprintln(stdout, "secret:", secret)
		return secret, nil
	}
	if len(positional) == 1 {
		return normalizeSecret(positional[0])
	}
	if env := os.Getenv("TOTP_SECRET"); env != "" {
		return normalizeSecret(env)
	}
	if f, ok := stdin.(*os.File); ok {
		if st, err := f.Stat(); err == nil && st.Mode()&os.ModeCharDevice != 0 {
			return "", errors.New("no secret: pass SECRET, set TOTP_SECRET, or pipe it to stdin (see --help)")
		}
	}
	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return normalizeSecret(line)
}

// watch prints the current code until interrupted, rewriting one line.
func watch(w io.Writer, key []byte, o *options, newHash func() hash.Hash) {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		now := time.Now()
		fmt.Fprintf(w, "\r%s  (%2ds) ", totp(key, now, o.period, o.digits, newHash), remaining(now, o.period))
		select {
		case <-stop:
			fmt.Fprintln(w)
			return
		case <-ticker.C:
		}
	}
}

// renderQR draws the code with half-block characters, two modules per text
// row, so it stays square and fits a normal terminal. The default assumes a
// dark terminal: light cells are drawn, dark ones left as background.
func renderQR(content string, invert bool) (string, error) {
	qr, err := qrcode.New(content, qrcode.Low)
	if err != nil {
		return "", fmt.Errorf("build QR code: %w", err)
	}
	bitmap := qr.Bitmap() // includes the quiet zone
	var b strings.Builder
	for y := 0; y < len(bitmap); y += 2 {
		for x := range bitmap[y] {
			top := bitmap[y][x] == invert
			bottom := false
			if y+1 < len(bitmap) {
				bottom = bitmap[y+1][x] == invert
			}
			switch {
			case top && bottom:
				b.WriteRune('█')
			case top:
				b.WriteRune('▀')
			case bottom:
				b.WriteRune('▄')
			default:
				b.WriteRune(' ')
			}
		}
		b.WriteByte('\n')
	}
	return b.String(), nil
}
