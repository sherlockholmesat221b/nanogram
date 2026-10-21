// File: cmd/ngcli/main.go

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/term"

	"gitlab.com/sherlockholmesat221b/nanogram/client"
	"gitlab.com/sherlockholmesat221b/nanogram/client/httptransport"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/wire"
)

const defaultServer = "http://127.0.0.1:8080"

type options struct {
	server string
	user   string
}

func parseOptions(command string, args []string) (options, error) {
	var o options
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&o.server, "server", defaultServer, "server URL")
	fs.StringVar(&o.user, "user", "", "username")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if fs.NArg() != 0 {
		return o, errors.New("unexpected positional arguments")
	}
	if o.user == "" {
		return o, errors.New("-user is required")
	}
	return o, nil
}

func readSecret(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		clear(b)
		return "", err
	}
	s := string(b)
	clear(b)
	return s, nil
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
	pass, err := client.GeneratePassphrase(client.DefaultPassphraseWords)
	if err != nil {
		return err
	}
	fmt.Printf("Write down this passphrase and keep it private:\n%s\n", pass)

	again, err := readSecret("Type the passphrase again to confirm: ")
	if err != nil {
		return err
	}
	if pass != again {
		return client.ErrPassphraseMismatch
	}

	c, err := newClient(o.server)
	if err != nil {
		return err
	}
	result, err := c.Register(ctx, o.user, pass, again, true)
	if err != nil {
		return err
	}

	fmt.Println("RECOVERY PHRASE — STORE OFFLINE.")
	fmt.Println("Write these 24 words on paper and keep them in a secure place.")
	fmt.Println("Never store them in an app, file, or cloud service.")
	fmt.Println(result.RecoveryPhrase)
	return nil
}

func login(ctx context.Context, o options, showDetails bool) error {
	pass, err := readSecret("Passphrase: ")
	if err != nil {
		return err
	}

	c, err := newClient(o.server)
	if err != nil {
		return err
	}
	session, err := c.Login(ctx, o.user, pass)
	clear([]byte(pass))
	if err != nil {
		if errors.Is(err, client.ErrLoginFailed) {
			return client.ErrLoginFailed
		}
		return err
	}
	defer session.Wipe()

	if !showDetails {
		blobs, err := c.T.AccountBlobs(
			ctx,
			session.Sign("GET", wire.PathAccountBlobs, nil),
		)
		if err != nil {
			return err
		}
		fmt.Println(len(blobs))
		return nil
	}

	fmt.Printf("User ID: %x\n", session.UserID)
	fmt.Printf("Scope: %s\n", session.Scope)
	for _, warning := range session.Warnings {
		fmt.Printf("Warning: %s\n", warning)
	}
	return nil
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: ngcli <register|login|blobs> -user USER")
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
		return login(context.Background(), o, true)
	case "blobs":
		return login(context.Background(), o, false)
	default:
		return errors.New("unknown command")
	}
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
}
