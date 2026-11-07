// File: cmd/ngcli/main_test.go

package main

import "testing"

func TestCheckServer(t *testing.T) {
	tests := []struct {
		raw      string
		insecure bool
		ok       bool
	}{
		{"http://127.0.0.1:8080", false, true},
		{"http://localhost:8080", false, true},
		{"http://[::1]:8080", false, true},
		{"https://example.com", false, true},
		{"https://example.com:8443/", false, true},
		{"http://abcdefghijklmnop.onion", false, true},
		{"http://example.com", false, false},
		{"http://192.168.1.20:8080", false, false},
		{"http://example.com", true, true},
		{"ftp://example.com", false, false},
		{"example.com", false, false},
		{"", false, false},
		{"https://example.com/api", false, false},
		{"https://user:secret@example.com", false, false},
		{"https://example.com?x=1", false, false},
		{"https://example.com#frag", false, false},
	}

	for _, tt := range tests {
		err := checkServer(tt.raw, tt.insecure)
		if (err == nil) != tt.ok {
			t.Fatalf("checkServer(%q, %v) = %v, want ok=%v", tt.raw, tt.insecure, err, tt.ok)
		}
	}
}

func TestParseOptionsNeedsAUser(t *testing.T) {
	if _, err := parseOptions("login", []string{"-server", "http://127.0.0.1:8080"}); err == nil {
		t.Fatal("a missing -user was accepted")
	}

	o, err := parseOptions("login", []string{"-user", "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if o.user != "alice" || o.server != defaultServer {
		t.Fatalf("options %+v", o)
	}
}

func TestParseOptionsChecksTheUsernameFormat(t *testing.T) {
	for _, user := range []string{"a-b", "ab", "has space", "wayyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy_too_long"} {
		if _, err := parseOptions("register", []string{"-user", user}); err == nil {
			t.Fatalf("the username %q was accepted", user)
		}
	}
}

func TestParseOptionsRefusesARemotePlainServer(t *testing.T) {
	if _, err := parseOptions("login", []string{"-user", "alice", "-server", "http://example.com"}); err == nil {
		t.Fatal("plain HTTP to a remote host was accepted")
	}
}
