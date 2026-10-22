// File: internal/e2e/username_test.go

package e2e

import (
	"context"
	"errors"
	"strings"
	"testing"

	"gitlab.com/sherlockholmesat221b/nanogram/client"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/auth"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/service"
)

// The client checks usernames before it contacts the server. This test makes
// sure its rule and the server's rule cannot drift apart.
func TestClientAndServerAgreeOnUsernames(t *testing.T) {
	s := newStack(t)

	oc, err := auth.NewConfiguration().Client()
	if err != nil {
		t.Fatal(err)
	}
	request := oc.RegistrationInit([]byte("x")).Serialize()

	names := []string{
		"alice", "bob", "a.b_c", "abc", "ab", "Alice", "al ice", "alice!",
		strings.Repeat("a", 32), strings.Repeat("a", 33), "", "ünï", "a-b", "x..y",
	}

	for _, name := range names {
		_, err := s.transport.RegisterStart(context.Background(), name, request, nil)

		serverAccepts := !errors.Is(err, service.ErrInvalidUsername)
		if err != nil && serverAccepts {
			t.Fatalf("%q: unexpected error %v", name, err)
		}

		if got := client.ValidUsername(name); got != serverAccepts {
			t.Fatalf("%q: client says %v, server says %v", name, got, serverAccepts)
		}
	}
}
