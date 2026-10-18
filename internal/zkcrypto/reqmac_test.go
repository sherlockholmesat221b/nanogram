// File: internal/zkcrypto/reqmac_test.go

package zkcrypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestRequestMACDeterministic(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	method := "GET"
	path := "/v1/account/blobs"
	counter := uint64(7)
	body := []byte("request body")

	first := RequestMAC(key, method, path, counter, body)
	second := RequestMAC(key, method, path, counter, body)

	if !bytes.Equal(first, second) {
		t.Fatal("RequestMAC is not deterministic")
	}

	if len(first) != 32 {
		t.Fatalf("RequestMAC length = %d, want 32", len(first))
	}
}

func TestRequestMACChangesWithInputs(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	method := "GET"
	path := "/v1/account/blobs"
	counter := uint64(7)
	body := []byte("request body")

	baseline := RequestMAC(key, method, path, counter, body)

	tests := []struct {
		name    string
		key     []byte
		method  string
		path    string
		counter uint64
		body    []byte
	}{
		{
			name:    "key",
			key:     bytes.Repeat([]byte{0x02}, 32),
			method:  method,
			path:    path,
			counter: counter,
			body:    body,
		},
		{
			name:    "method",
			key:     key,
			method:  "POST",
			path:    path,
			counter: counter,
			body:    body,
		},
		{
			name:    "path",
			key:     key,
			method:  method,
			path:    "/v1/account/keys",
			counter: counter,
			body:    body,
		},
		{
			name:    "counter",
			key:     key,
			method:  method,
			path:    path,
			counter: counter + 1,
			body:    body,
		},
		{
			name:    "body",
			key:     key,
			method:  method,
			path:    path,
			counter: counter,
			body:    []byte("different request body"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RequestMAC(
				tt.key,
				tt.method,
				tt.path,
				tt.counter,
				tt.body,
			)

			if bytes.Equal(got, baseline) {
				t.Fatalf("RequestMAC did not change when %s changed", tt.name)
			}
		})
	}
}

func TestRequestMACGolden(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)

	got := RequestMAC(
		key,
		"GET",
		"/v1/account/blobs",
		7,
		nil,
	)

	const wantHex = "0e95fae7ee95ce323927ebd6d26680c02413f5bfd1b49602be0a00f5dd4fc6d5"

	if gotHex := hex.EncodeToString(got); gotHex != wantHex {
		t.Fatalf("RequestMAC() = %s, want %s", gotHex, wantHex)
	}
}

func TestVerifyRequestMAC(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	method := "GET"
	path := "/v1/account/blobs"
	counter := uint64(7)
	body := []byte("request body")

	mac := RequestMAC(key, method, path, counter, body)

	tests := []struct {
		name string
		mac  []byte
		want bool
	}{
		{
			name: "correct MAC",
			mac:  mac,
			want: true,
		},
		{
			name: "wrong MAC",
			mac: func() []byte {
				wrong := append([]byte(nil), mac...)
				wrong[0] ^= 0x01
				return wrong
			}(),
			want: false,
		},
		{
			name: "short MAC",
			mac:  mac[:len(mac)-1],
			want: false,
		},
		{
			name: "nil MAC",
			mac:  nil,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := VerifyRequestMAC(
				key,
				method,
				path,
				counter,
				body,
				tt.mac,
			)

			if got != tt.want {
				t.Fatalf("VerifyRequestMAC() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRequestKey(t *testing.T) {
	sessionKey := bytes.Repeat([]byte{0x01}, 32)

	got, err := RequestKey(sessionKey)
	if err != nil {
		t.Fatalf("RequestKey() error = %v", err)
	}

	want, err := DeriveKey(sessionKey, LabelRequest)
	if err != nil {
		t.Fatalf("DeriveKey() error = %v", err)
	}

	if !bytes.Equal(got, want) {
		t.Fatal("RequestKey() does not match DeriveKey(sessionKey, LabelRequest)")
	}
}

func TestRecoveryCredentialIDGolden(t *testing.T) {
	userID := bytes.Repeat([]byte{0x04}, 16)

	got, err := RecoveryCredentialID(userID)
	if err != nil {
		t.Fatalf("RecoveryCredentialID() error = %v", err)
	}

	const wantHex = "c189e4cf3577eaed1313cf3b7bd44263"

	if gotHex := hex.EncodeToString(got); gotHex != wantHex {
		t.Fatalf("RecoveryCredentialID() = %s, want %s", gotHex, wantHex)
	}

	if len(got) != 16 {
		t.Fatalf("RecoveryCredentialID() length = %d, want 16", len(got))
	}
}

func TestRecoveryCredentialIDRejectsInvalidUserIDLengths(t *testing.T) {
	tests := []struct {
		name   string
		userID []byte
	}{
		{
			name:   "nil",
			userID: nil,
		},
		{
			name:   "15 bytes",
			userID: make([]byte, 15),
		},
		{
			name:   "17 bytes",
			userID: make([]byte, 17),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RecoveryCredentialID(tt.userID)

			if err == nil {
				t.Fatal("RecoveryCredentialID() error = nil, want error")
			}

			if got != nil {
				t.Fatalf("RecoveryCredentialID() = %x, want nil", got)
			}
		})
	}
}
