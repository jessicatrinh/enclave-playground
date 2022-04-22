package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"time"

	"github.com/jessicatrinh/nsm"
	"github.com/jessicatrinh/nsm/request"
)

// generateBigPrime reads entropy from Nitro Secure Module (https://github.com/hf/nsm)
func generateBigPrime() (*big.Int, error) {
	sess, err := nsm.OpenDefaultSession()
	defer sess.Close()

	if nil != err {
		return nil, err
	}

	return rand.Prime(sess, 2048)
}

// attest obtain an attestation document from Nitro Hypervisor (https://github.com/hf/nsm)
func attest(nonce, userData, publicKey []byte) ([]byte, error) {
	sess, err := nsm.OpenDefaultSession()
	defer sess.Close()

	if nil != err {
		return nil, err
	}

	res, err := sess.Send(&request.Attestation{
		Nonce:     nonce,
		UserData:  userData,
		PublicKey: publicKey,
	})
	if nil != err {
		return nil, err
	}

	if "" != res.Error {
		return nil, errors.New(string(res.Error))
	}

	if nil == res.Attestation || nil == res.Attestation.Document {
		return nil, errors.New("NSM device did not return an attestation")
	}

	return res.Attestation.Document, nil
}

// HELPER:

func StreamToByte(stream io.Reader) []byte {
	buf := new(bytes.Buffer)
	buf.ReadFrom(stream)
	return buf.Bytes()
}

func main() {
	// Use NSM's random number generator
	randomInt, err := generateBigPrime()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	random := bytes.NewReader(randomInt.Bytes())
	// random := rand.Reader // Uncomment for TEST
	// Generate a keypair with ECC
	curve := elliptic.P256()
	xprv, err := ecdsa.GenerateKey(curve, random)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	xpub := xprv.Public()
	userData := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	// Retrieve attestation document
	att, err := attest(StreamToByte(random), userData, xpub.([]byte))
	fmt.Printf("attestation %v %v\n", base64.StdEncoding.EncodeToString(att), err)
	for {
		time.Sleep(1 * time.Second)
		fmt.Println("Running attest")
	}
}
