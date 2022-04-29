package main

import (
	"encoding/base64"
	"fmt"
	"nitro/attest/attestation"
	"time"
)

func main() {
	for {
		nonce, err := attestation.CreateNonce(time.Second * 1) // temporary
		attestation.LogIfError(err)
		fmt.Println("Generating keypair")
		xpub, err := attestation.GetXpub()
		attestation.LogIfError(err)
		userData := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11} // sample userData
		fmt.Println("Generating attestation doc")
		doc, err := attestation.GetDoc(nonce.Value, userData, xpub)
		attestation.LogIfError(err)
		fmt.Printf("doc: %v\n", base64.StdEncoding.EncodeToString(doc))

		time.Sleep(5 * time.Second)
	}
}
