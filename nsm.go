package main

import (
	"fmt"
	"nitro/attest/attestation"
	"time"
)

func main() {
	nonce, err := attestation.CreateNonce(time.Second * 1)
	if err != nil {
		fmt.Errorf("cannot create nonce: %v", err)
	}
	userData := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	attestation.Attest(nonce, userData)
}
