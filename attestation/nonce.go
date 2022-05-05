package attestation

import (
	"crypto/rand"
	"math"
	"math/big"
	"time"
)

// Nonce contains two fields:
// Value is a random byte array,
// expiration is the time at which the nonce expires.
type Nonce struct {
	Value      []byte
	Expiration time.Time
}

// CreateNonce generates a limited lifetime nonce.
// Pre: Parameter secs is the number of seconds for which the nonce will be valid.
// Post: A Nonce object or error is returned.
func CreateNonce(secs time.Duration) (*Nonce, error) {
	random, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return nil, err
	}
	return &Nonce{
		Value:      random.Bytes(),
		Expiration: time.Now().Add(secs),
	}, nil
}

// isExpiredNonce checks whether a nonce has expired in relation to the current time.
// Pre: Parameter n is a *Nonce.
// Post: True is returned if the nonce has expired. False is returned if the nonce has not expired.
func isExpiredNonce(n *Nonce) bool {
	if time.Now().After(n.Expiration) {
		return true
	}
	return false
}
