// File: internal/wire/password_test.go

package wire

import (
	"bytes"
	"encoding/json"
	"testing"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/service"
)

func TestPasswordJSONFormatIsStable(t *testing.T) {
	got, err := json.Marshal(PasswordStartRequest{PasswordRequest: []byte{1, 2, 3}})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"password_request":"AQID"}` {
		t.Fatalf("got %s", got)
	}

	got, err = json.Marshal(PasswordBeginRequest{ExpectedVersion: 2, Record: []byte{1}, KEK: Blob{Kind: 1, Version: 3}})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"expected_version":2,"record":"AQ==","kek":{"kind":1,"version":3,"prev_hash":null,"data":null}}` {
		t.Fatalf("got %s", got)
	}
}

func TestUploadRoundTrip(t *testing.T) {
	in := service.BlobUpload{Kind: 1, Version: 5, PrevHash: [32]byte{3, 4}, Data: []byte("kek")}

	out, err := BlobFromUpload(in).ToUpload()
	if err != nil {
		t.Fatal(err)
	}

	if out.Kind != in.Kind || out.Version != in.Version || out.PrevHash != in.PrevHash || !bytes.Equal(out.Data, in.Data) {
		t.Fatalf("round trip changed the upload: %+v", out)
	}
}
