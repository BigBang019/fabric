package request

import (
	"crypto/rand"
	"encoding/hex"

	providersFab "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/cryptosuite"
	"github.com/pkg/errors"
)

const (
	// NonceSize is the default NonceSize
	NonceSize = 24
)

// GetRandomBytes returns len random looking bytes
func GetRandomBytes(len int) ([]byte, error) {
	key := make([]byte, len)

	// TODO: rand could fill less bytes then len
	_, err := rand.Read(key)
	if err != nil {
		return nil, errors.Wrap(err, "error getting random bytes")
	}

	return key, nil
}

// GetRandomNonce returns a random byte array of length NonceSize
func GetRandomNonce() ([]byte, error) {
	return GetRandomBytes(NonceSize)
}

func ComputeTxnID(ctx providersFab.ClientContext, nonce []byte, creator []byte) (string, error) {
	ho := cryptosuite.GetSHA256Opts()
	h, err := ctx.CryptoSuite().GetHash(ho)
	if err != nil {
		return "", errors.WithMessage(err, "hash function creation failed")
	}
	b := append(nonce, creator...)
	_, err = h.Write(b)
	if err != nil {
		return "", err
	}
	digest := h.Sum(nil)
	id := hex.EncodeToString(digest)
	return id, nil
}
