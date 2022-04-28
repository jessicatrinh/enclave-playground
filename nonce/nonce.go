package nonce

import (
	"crypto/rand"
	"math"
	"math/big"
	"time"
)

var (
	secs = time.Second * 2 // number of seconds for which nonce is valid
)

type Nonce struct {
	Value      []byte
	expiration time.Time // time at which nonce expires
}

// CreateNonce generates a limited lifetime nonce
func CreateNonce() (*Nonce, error) {
	random, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return nil, err
	}
	return &Nonce{
		Value:      random.Bytes(),
		expiration: time.Now().Add(secs),
	}, nil
}

func isExpiredNonce(n *Nonce) bool {
	if time.Now().After(n.expiration) {
		return true
	}
	return false
}
