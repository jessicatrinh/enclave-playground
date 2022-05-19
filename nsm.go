package main

import (
	"encoding/base64"
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
	fmt.Println("nonce:", nonce)
	fmt.Println("nonce.Value:", nonce.Value)
	nonceValEncoded := base64.StdEncoding.EncodeToString(nonce.Value)
	fmt.Println(nonceValEncoded)
	fmt.Println("nonce.Expiration:", nonce.Expiration)
	fmt.Println("nonceExpStr", nonce.Expiration.String())
	fmt.Println("Generating keypair")
	xpub, xprv, err := attestation.GenerateKeypair()
	fmt.Println("xprv:", xprv) // for TESTING
	attestation.LogIfError(err)
	fmt.Println("Generating attestation doc")
	doc, err := attestation.RetrieveAttestation(nonce.Value, userData, xpub)
	attestation.LogIfError(err)
	fmt.Printf("doc: %v\n", base64.StdEncoding.EncodeToString(doc))
	for {
		fmt.Println("Sample print statement")
		time.Sleep(5 * time.Second)
	}
}
