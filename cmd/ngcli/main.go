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

func parseOptions(command string, args []string) (options, error) {
	var o options

	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&o.server, "server", defaultServer, "server URL")
	fs.StringVar(&o.user, "user", "", "username")
	fs.BoolVar(&o.insecure, "insecure", false, "allow plain HTTP to a server that is not this machine or an onion address")

	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if fs.NArg() != 0 {
		return o, errors.New("unexpected positional arguments")
	}
	if o.user == "" {
		return o, errors.New("-user is required")
	}
	if !client.ValidUsername(o.user) {
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

func newClient(server string) (*client.Client, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return nil, err
	}

	heads, err := client.NewFileHeads(filepath.Join(dir, "nanogram", "heads.json"))
	if err != nil {
		return nil, err
	}

	return client.New(httptransport.New(server, nil), heads), nil
}

func register(ctx context.Context, o options) error {
	if err := requireTerminal(); err != nil {
		return err
	}

	c, err := newClient(o.server)
	if err != nil {
		return err
	}

	pass, err := client.GeneratePassphrase(client.DefaultPassphraseWords)
	if err != nil {
		return err
	}
	fmt.Printf("Write down this passphrase and keep it private:\n%s\n", pass)

	again, err := readSecret("Type the passphrase again to confirm: ")
	if err != nil {
		return err
	}

	result, err := c.Register(ctx, o.user, pass, again, true)
	if err != nil {
		return err
	}

	fmt.Println("RECOVERY PHRASE: STORE OFFLINE.")
	fmt.Println("Write these 24 words on paper and keep them in a secure place.")
	fmt.Println("Never store them in an app, file, or cloud service.")
	fmt.Println(result.RecoveryPhrase)

	return nil
}

// login logs in. With countBlobs it then asks for the blobs once more and
// prints how many there are, otherwise it prints the user id and the scope.
func login(ctx context.Context, o options, countBlobs bool) error {
	c, err := newClient(o.server)
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

func run(args []string) error {
	fmt.Fprintln(os.Stderr, "ngcli is a test tool for developers. Do not use it for accounts you care about.")

	if len(args) == 0 {
		return errors.New("usage: ngcli <register|login|blobs> -user USER [-server URL]")
	}

	command := args[0]

	o, err := parseOptions(command, args[1:])
	if err != nil {
		return err
	}

	switch command {
	case "register":
		return register(context.Background(), o)
	case "login":
		return login(context.Background(), o, false)
	case "blobs":
		return login(context.Background(), o, true)
	default:
		return fmt.Errorf("unknown command %q (use register, login or blobs)", command)
	}
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
}
