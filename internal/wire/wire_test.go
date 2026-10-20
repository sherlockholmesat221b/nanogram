// File: internal/wire/wire_test.go

package wire

import (
	"bytes"
	"encoding/json"
	"testing"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/service"
)

func TestJSONFormatIsStable(t *testing.T) {
	tests := []struct {
		name string
		v    any
		want string
	}{
		{
			"login start",
			LoginStartRequest{Username: "alice", Kind: "password", KE1: []byte{1, 2, 3}},
			`{"username":"alice","kind":"password","ke1":"AQID"}`,
		},
		{
			"login finish",
			LoginFinishRequest{LoginID: []byte{1}, KE3: []byte{2}},
			`{"login_id":"AQ==","ke3":"Ag=="}`,
		},
		{
			"register start without recovery",
			RegisterStartRequest{Username: "alice", PasswordRequest: []byte{1, 2, 3}},
			`{"username":"alice","password_request":"AQID"}`,
		},
		{
			"error",
			ErrorResponse{Error: "unauthorized"},
			`{"error":"unauthorized"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.v)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Fatalf("got %s, want %s", got, tt.want)
			}
		})
	}
}

func TestBlobRoundTrip(t *testing.T) {
	info := service.BlobInfo{
		Kind:     2,
		Version:  7,
		PrevHash: [32]byte{9, 8, 7},
		Data:     []byte("blob"),
	}

	wireBlob := BlobFromInfo(info)

	// Through JSON and back, as on the network.
	encoded, err := json.Marshal(wireBlob)
	if err != nil {
		t.Fatal(err)
	}

	var decoded Blob
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}

	upload, err := decoded.ToUpload()
	if err != nil {
		t.Fatal(err)
	}

	if upload.Kind != info.Kind ||
		upload.Version != info.Version ||
		upload.PrevHash != info.PrevHash ||
		!bytes.Equal(upload.Data, info.Data) {
		t.Fatalf("round trip changed the blob: %+v", upload)
	}
}

func TestBlobRejectsWrongHashLength(t *testing.T) {
	for _, n := range []int{0, 31, 33} {
		b := Blob{Kind: 1, Version: 1, PrevHash: make([]byte, n), Data: []byte("x")}
		if _, err := b.ToUpload(); err == nil {
			t.Fatalf("a %d byte hash was accepted", n)
		}
	}
}

func TestRegisterFinishRoundTrip(t *testing.T) {
	in := service.RegisterFinishRequest{
		UserID:         bytes.Repeat([]byte{1}, 16),
		Username:       "alice",
		PasswordRecord: []byte("password record"),
		RecoveryRecord: []byte("recovery record"),
		Blobs: []service.BlobUpload{
			{Kind: 1, Version: 1, Data: []byte("kek")},
			{Kind: 4, Version: 1, PrevHash: [32]byte{5}, Data: []byte("recovery")},
		},
		PublicKeys: []service.PublicKeyUpload{
			{Kind: "mlkem", Key: []byte("k1")},
			{Kind: "sign", Key: []byte("k2")},
		},
	}

	encoded, err := json.Marshal(RegisterFinishFromService(in))
	if err != nil {
		t.Fatal(err)
	}

	var decoded RegisterFinishRequest
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}

	out, err := decoded.ToService()
	if err != nil {
		t.Fatal(err)
	}

	if out.Username != in.Username ||
		!bytes.Equal(out.UserID, in.UserID) ||
		!bytes.Equal(out.PasswordRecord, in.PasswordRecord) ||
		!bytes.Equal(out.RecoveryRecord, in.RecoveryRecord) ||
		len(out.Blobs) != 2 ||
		out.Blobs[1].PrevHash != in.Blobs[1].PrevHash ||
		len(out.PublicKeys) != 2 ||
		out.PublicKeys[1].Kind != "sign" {
		t.Fatalf("round trip changed the request: %+v", out)
	}
}

func TestRegisterFinishRejectsBadBlobHash(t *testing.T) {
	r := RegisterFinishRequest{
		Blobs: []Blob{{Kind: 1, Version: 1, PrevHash: []byte{1, 2, 3}}},
	}

	if _, err := r.ToService(); err == nil {
		t.Fatal("a blob with a short previous hash was accepted")
	}
}
