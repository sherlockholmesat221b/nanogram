// File: cmd/ngcli/main.go

// Command ngcli is a command line client for trying out and testing nanogram.
// It is a developer tool, not a finished client, and it is not for accounts
// you care about. It exists to exercise the whole system from a terminal.
//
// Known limits: passphrases are handled as Go strings, which cannot be wiped
// from memory; the terminal keeps what it shows (the passphrase and the
// recovery words) in its scrollback; two copies running at once can overwrite
// each other's remembered blob versions; and there is no Tor proxy option yet.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"

	"gitlab.com/sherlockholmesat221b/nanogram/client"
	"gitlab.com/sherlockholmesat221b/nanogram/client/httptransport"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/wire"
)

const defaultServer = "http://127.0.0.1:8080"

type options struct {
	server   string
	user     string
	insecure bool
	accept   bool
}

// checkServer accepts https, and plain http only to this machine or to an
// onion address, where the connection is protected anyway. Anything else
// needs -insecure. The URL must be just a scheme, a host and a port, because
// the API paths are absolute and are signed as they are.
func checkServer(raw string, insecure bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return errors.New("-server must be a URL like http://127.0.0.1:8080")
	}
	if u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("-server must be only a scheme, a host and a port")
	}

	switch u.Scheme {
	case "https":
		return nil

	case "http":
		host := u.Hostname()

		if insecure || host == "localhost" || strings.HasSuffix(host, ".onion") {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}

		return errors.New("refusing plain HTTP to a remote server (use https, an onion address, or -insecure)")

	default:
		return errors.New("-server must start with http:// or https://")
	}
}

func parseOptions(command string, args []string, requireUser bool) (options, error) {
	var o options

	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&o.server, "server", defaultServer, "server URL")
	fs.StringVar(&o.user, "user", "", "username")
	fs.BoolVar(&o.insecure, "insecure", false, "allow plain HTTP to a server that is not this machine or an onion address")
	fs.BoolVar(&o.accept, "accept", false, "accept the current server fingerprint as the pin")

	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if fs.NArg() != 0 {
		return o, errors.New("unexpected positional arguments")
	}
	if requireUser && o.user == "" {
		return o, errors.New("-user is required")
	}
	if o.user != "" && !client.ValidUsername(o.user) {
		return o, errors.New("invalid username: use 3 to 32 characters from a-z, 0-9, _ and .")
	}

	return o, checkServer(o.server, o.insecure)
}

// readSecret reads a line from the terminal without echo. The result is a Go
// string and cannot be wiped, which is a known limit of this tool.
func readSecret(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)

	defer clear(b)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

// requireTerminal refuses to go on when standard output is not a terminal, so
// that a passphrase is never written into a file or a log by a redirect.
func requireTerminal() error {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return errors.New("refusing to show secrets: standard output is not a terminal")
	}

	return nil
}

func newClient(server string) (*client.Client, client.PinStore, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return nil, nil, err
	}

	heads, err := client.NewFileHeads(filepath.Join(dir, "nanogram", "heads.json"))
	if err != nil {
		return nil, nil, err
	}

	pins, err := client.NewFilePins(filepath.Join(dir, "nanogram", "pins.json"), server)
	if err != nil {
		return nil, nil, err
	}

	return client.New(httptransport.New(server, nil), heads, pins), pins, nil
}

func register(ctx context.Context, o options) error {
	if err := requireTerminal(); err != nil {
		return err
	}

	c, _, err := newClient(o.server)
	if err != nil {
		return err
	}

	pass, err := readSecret("Password: ")
	if err != nil {
		return err
	}

	again, err := readSecret("Confirm the password: ")
	if err != nil {
		return err
	}

	result, err := c.Register(ctx, o.user, pass, again, true)
	if err != nil {
		return err
	}

	for _, w := range result.Warnings {
		fmt.Fprintf(os.Stderr, "Warning: %s\n", w)
	}

	// How to hand over the recovery phrase safely is still undecided. For now
	// it is shown on the terminal once, and never written anywhere.
	fmt.Println("RECOVERY PHRASE: STORE OFFLINE.")
	fmt.Println("Write these 24 words on paper and keep them in a secure place.")
	fmt.Println("Never store them in an app, file, or cloud service.")
	fmt.Println(result.RecoveryPhrase)

	return nil
}

// suggest prints a generated passphrase, for people who want one.
func suggest() error {
	if err := requireTerminal(); err != nil {
		return err
	}

	passphrase, err := client.GeneratePassphrase(client.DefaultPassphraseWords)
	if err != nil {
		return err
	}

	fmt.Println(passphrase)
	return nil
}

// passwd changes the password: it logs in with the current one, then asks for
// the new one twice.
func passwd(ctx context.Context, o options) error {
	c, _, err := newClient(o.server)
	if err != nil {
		return err
	}

	current, err := readSecret("Current password: ")
	if err != nil {
		return err
	}

	session, err := c.Login(ctx, o.user, current)
	if err != nil {
		if errors.Is(err, client.ErrLoginFailed) {
			return client.ErrLoginFailed
		}
		return err
	}
	defer session.Wipe()

	pass, err := readSecret("New password: ")
	if err != nil {
		return err
	}

	again, err := readSecret("Confirm the new password: ")
	if err != nil {
		return err
	}

	fresh, err := c.ChangePassword(ctx, session, pass, again)
	if err != nil {
		return err
	}
	fresh.Wipe()

	fmt.Println("Password changed. Every other session has ended.")
	return nil
}

// recover resets the password using the 24-word recovery phrase, then rotates
// the phrase and shows the new one once.
func recoverPassword(ctx context.Context, o options) error {
	if err := requireTerminal(); err != nil {
		return err
	}

	c, _, err := newClient(o.server)
	if err != nil {
		return err
	}

	phrase, err := readSecret("Recovery phrase: ")
	if err != nil {
		return err
	}

	pass, err := readSecret("New password: ")
	if err != nil {
		return err
	}

	again, err := readSecret("Confirm the new password: ")
	if err != nil {
		return err
	}

	session, err := c.RecoverWithPhrase(ctx, o.user, phrase, pass, again)
	if err != nil {
		if errors.Is(err, client.ErrLoginFailed) {
			return errors.New("recovery failed: wrong phrase, or recovery is not set up")
		}
		return err
	}
	defer session.Wipe()

	fmt.Println("Password changed. Every other session has ended.")

	newPhrase, err := c.RotateRecovery(ctx, session)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: the recovery phrase was not rotated: %v\n", err)
		fmt.Fprintln(os.Stderr, "the old phrase still works; run 'ngcli recover' again to rotate it")
		return nil
	}

	fmt.Println("NEW RECOVERY PHRASE: STORE OFFLINE.")
	fmt.Println("The old phrase no longer works.")
	fmt.Println(newPhrase)
	return nil
}

// login logs in. With countBlobs it then asks for the blobs once more and
// prints how many there are, otherwise it prints the user id and the scope.
func login(ctx context.Context, o options, countBlobs bool) error {
	c, _, err := newClient(o.server)
	if err != nil {
		return err
	}

	pass, err := readSecret("Passphrase: ")
	if err != nil {
		return err
	}

	session, err := c.Login(ctx, o.user, pass)
	if err != nil {
		if errors.Is(err, client.ErrLoginFailed) {
			return client.ErrLoginFailed
		}
		return err
	}
	defer session.Wipe()

	for _, warning := range session.Warnings {
		fmt.Fprintf(os.Stderr, "Warning: %s\n", warning)
	}

	if session.RecentFailures.Count > 0 {
		fmt.Fprintf(os.Stderr, "%d attempt(s) on your name since your last login (first %s, last %s)\n",
			session.RecentFailures.Count,
			session.RecentFailures.First.Format(time.RFC3339),
			session.RecentFailures.Last.Format(time.RFC3339))
	}

	if countBlobs {
		blobs, err := c.T.AccountBlobs(ctx, session.Sign("GET", wire.PathAccountBlobs, nil))
		if err != nil {
			return err
		}

		fmt.Println(len(blobs))
		return nil
	}

	fmt.Printf("User ID: %x\n", session.UserID)
	fmt.Printf("Scope: %s\n", session.Scope)

	return nil
}

// reportNewPin prints the fingerprint once, the first time a pin is
// established, so the user can compare it with the published one.
func reportNewPin(pins client.PinStore, wasPinned bool) {
	if wasPinned || pins == nil {
		return
	}
	if key, ok := pins.Get(); ok {
		fmt.Fprintf(os.Stderr, "Server fingerprint (first contact): %s\n", client.Fingerprint(key))
		fmt.Fprintln(os.Stderr, "Compare this with the fingerprint published by the server operator.")
	}
}

func pinServer(ctx context.Context, o options) error {
	dir, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	pins, err := client.NewFilePins(filepath.Join(dir, "nanogram", "pins.json"), o.server)
	if err != nil {
		return err
	}

	c := client.New(httptransport.New(o.server, nil), nil, nil)
	info, err := c.ServerInfo(ctx)
	if err != nil {
		return err
	}
	fp := client.Fingerprint(info.PublicKey)

	onionWarning, onionErr := client.CheckOnion(o.server, info.PublicKey, info.OnionSignature)

	var onionStatus string
	switch {
	case onionErr != nil:
		onionStatus = "INVALID (signature does not match the .onion address)"
	case onionWarning != "":
		onionStatus = "not signed (operator has not configured -onion-key)"
	case len(info.OnionSignature) > 0:
		onionStatus = "verified (signature matches the .onion address)"
	default:
		onionStatus = "not applicable (not a .onion address)"
	}

	if o.accept {
		if onionErr != nil {
			return fmt.Errorf("refusing to pin: %w", onionErr)
		}
		if err := pins.Put(info.PublicKey); err != nil {
			return err
		}
		fmt.Printf("Pinned: %s\n", fp)
		fmt.Printf("Onion:  %s\n", onionStatus)
		fmt.Println("Confirm this matches the fingerprint published by the operator.")
		return nil
	}

	fmt.Printf("Server:      %s\n", o.server)
	fmt.Printf("Fingerprint: %s\n", fp)
	fmt.Printf("Onion:       %s\n", onionStatus)

	if pinned, ok := pins.Get(); ok {
		existing := client.Fingerprint(pinned)
		if existing == fp {
			fmt.Printf("Pinned:      %s (matches)\n", existing)
		} else {
			fmt.Printf("Pinned:      %s (MISMATCH)\n", existing)
			fmt.Println("If the change is expected, run 'ngcli pin --accept'. Otherwise do not proceed.")
		}
	} else {
		fmt.Println("Pinned:      no")
		fmt.Println("If the fingerprint matches the operator's published one, run 'ngcli pin --accept'.")
	}

	return nil
}

func forgetPin(o options) error {
	dir, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	pins, err := client.NewFilePins(filepath.Join(dir, "nanogram", "pins.json"), o.server)
	if err != nil {
		return err
	}
	if err := pins.Clear(); err != nil {
		return err
	}
	fmt.Println("Pin forgotten.")
	return nil
}

func run(args []string) error {
	fmt.Fprintln(os.Stderr, "ngcli is a test tool for developers. Do not use it for accounts you care about.")

	if len(args) == 0 {
		return errors.New("usage: ngcli <register|login|passwd|recover|blobs|pin|forget-pin> [-user USER] [-server URL], or ngcli suggest")
	}
	command := args[0]

	if command == "suggest" {
		return suggest()
	}

	requireUser := command != "pin" && command != "forget-pin"
	o, err := parseOptions(command, args[1:], requireUser)
	if err != nil {
		return err
	}

	switch command {
	case "register":
		return register(context.Background(), o)
	case "login":
		return login(context.Background(), o, false)
	case "passwd":
		return passwd(context.Background(), o)
	case "recover":
		return recoverPassword(context.Background(), o)
	case "blobs":
		return login(context.Background(), o, true)
	case "pin":
		return pinServer(context.Background(), o)
	case "forget-pin":
		return forgetPin(o)
	default:
		return fmt.Errorf("unknown command %q (use register, login, passwd, recover, blobs, pin, forget-pin or suggest)", command)
	}
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
}
