// File: cmd/server/main.go

// Command server runs the HTTP API with an in-memory store. Everything is lost
// when it stops, so it is for trying the system out, not for real accounts.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/api"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/auth"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/service"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/store/memstore"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// build loads the server keys and returns the store and the HTTP handler.
func build(keysPath string, logger *log.Logger) (*memstore.MemStore, http.Handler, error) {
	keys, err := auth.LoadServerKeys(keysPath)
	if err != nil {
		return nil, nil, err
	}

	st := memstore.New()

	svc := service.New(service.Config{
		Auth:  auth.NewServer(keys),
		Store: st,
	})

	return st, api.New(svc, logger), nil
}

func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.SetOutput(stderr)

	addr := fs.String("addr", "127.0.0.1:8080", "address to listen on")
	keysPath := fs.String("keys", "server-keys.json", "path of the server key file")
	initKeys := fs.Bool("init-keys", false, "create the key file and exit")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *initKeys {
		keys := auth.GenerateServerKeys(auth.NewConfiguration())
		if err := keys.Save(*keysPath); err != nil {
			return err
		}

		fmt.Fprintf(stdout, "server keys written to %s\n", *keysPath)
		return nil
	}

	logger := log.New(stderr, "", log.LstdFlags)

	st, handler, err := build(*keysPath, logger)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              *addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Expired reservations, login states and sessions are removed once a minute.
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				if err := st.DeleteExpired(ctx, now); err != nil && ctx.Err() == nil {
					logger.Printf("cleanup failed: %v", err)
				}
			}
		}
	}()

	failed := make(chan error, 1)
	go func() {
		failed <- srv.ListenAndServe()
	}()

	logger.Printf("listening on %s (plain HTTP, in-memory store)", *addr)

	select {
	case err := <-failed:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
	}

	logger.Print("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return srv.Shutdown(shutdownCtx)
}
