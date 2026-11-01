# totp-cli

Generates time-based one-time passwords (TOTP, RFC 6238) from a base32 secret.
Codes match [it-tools' OTP generator](https://it-tools.tech/otp-generator) and
authenticator apps. Ships as a single static binary for Windows and Linux.

## Download

Prebuilt binaries for Windows and Linux are on the
[releases page](https://github.com/5566brs/totp-cli/releases/latest). They have
no dependencies: download one and run it. `sha256sums.txt` lists their checksums.

## Build

Requires Go 1.22 or later.

```sh
go install github.com/5566brs/totp-cli@latest
```

Or from a checkout:

```sh
go build -o totp .
```

Cross-compile from any platform:

```sh
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/totp-windows-amd64.exe .
CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/totp-linux-amd64 .
CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o dist/totp-linux-arm64 .
```

## Usage

```sh
totp JBSWY3DPEHPK3PXP                          # current code
totp -t 2026-11-01T12:00:00Z JBSWY3DPEHPK3PXP  # code for a given time
totp -p 60 -d 8 -a SHA256 JBSWY3DPEHPK3PXP     # custom period, length, hash
totp --watch JBSWY3DPEHPK3PXP                  # live code with a countdown
totp --qr --issuer GitHub --account me@example.com JBSWY3DPEHPK3PXP
totp --generate --qr                           # new random secret and QR code
```

Run `totp --help` for every flag.

The code goes to stdout and the time left to stderr, so
`code=$(totp "$SECRET")` captures only the code.

### Keeping the secret out of your shell history

Command-line arguments are saved in shell history and visible in process
lists. Use the environment or stdin for real secrets:

```sh
TOTP_SECRET=... totp      # Linux
totp < secret.txt         # any platform
```

### QR code colors

The QR code is drawn for dark terminals. On a light terminal, or if a phone
can't read it, add `--invert`.

## Differences from it-tools

Defaults match it-tools: SHA1, 6 digits, 30 seconds, issuer `IT-Tools`,
account `demo-user`. The site itself only generates that SHA1, 6-digit,
30-second form; the other values here are extras that authenticator apps
may or may not support.

If a secret's length is not a multiple of 8 characters, it-tools decodes it
differently from RFC 4648 and from authenticator apps, so its codes differ.
`totp` follows the RFC, because those are the codes that services accept. When
the two would disagree it prints a note, and `--it-tools` reproduces the
site's output.
