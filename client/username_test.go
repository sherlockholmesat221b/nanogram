// File: client/username_test.go

package client

import (
	"strings"
	"testing"
)

func TestValidUsername(t *testing.T) {
	tests := []struct {
		name string
		ok   bool
	}{
		{"alice", true},
		{"a.b_c", true},
		{"abc", true},
		{strings.Repeat("a", 32), true},
		{"ab", false},
		{strings.Repeat("a", 33), false},
		{"", false},
		{"Alice", false},
		{"al ice", false},
		{"alice!", false},
		{"a-b", false},
		{"ünï", false},
		{"alice\n", false},
	}

	for _, tt := range tests {
		if got := ValidUsername(tt.name); got != tt.ok {
			t.Fatalf("ValidUsername(%q) = %v, want %v", tt.name, got, tt.ok)
		}
	}
}
