package main

import (
	"fmt"
	"math/big"
	"time"
)

var (
	secs = time.Second * 2 // number of seconds for which nonce is valid
)

type Nonce struct {
	value      []byte
	creation   time.Time // time at which nonce was created
	expiration time.Time // time at which nonce expires
}

// createNonce generates a limited lifetime nonce
func createNonce(random *big.Int) *Nonce {
	return &Nonce{
		value:      random.Bytes(),
		creation:   time.Now(),
		expiration: time.Now().Add(secs),
	}
}

func isExpiredNonce(n *Nonce) bool {
	if time.Now().After(n.expiration) {
		return true
	}
	return false
}

func main() {
	random := big.NewInt(251364)
	nonce := createNonce(random)
	time.Sleep(time.Second * 1)
	//time.Sleep(secs)
	if isExpiredNonce(nonce) {
		fmt.Println("Nonce is expired")
	} else {
		fmt.Println("Nonce is valid")
	}
}
