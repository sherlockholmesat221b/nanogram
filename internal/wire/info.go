// File: internal/wire/info.go

package wire

import "gitlab.com/sherlockholmesat221b/nanogram/internal/service"

// ToInfo converts a wire blob to the service type. It fails when the previous
// hash is not exactly 32 bytes.
func (b Blob) ToInfo() (service.BlobInfo, error) {
	prev, err := toHash(b.PrevHash)
	if err != nil {
		return service.BlobInfo{}, err
	}

	return service.BlobInfo{
		Kind:     b.Kind,
		Version:  b.Version,
		PrevHash: prev,
		Data:     b.Data,
	}, nil
}
