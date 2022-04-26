package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/jessicatrinh/nsm"
	"github.com/jessicatrinh/nsm/request"
	"io"
	"math/big"
	"time"
)

func main() {
	for {
		fmt.Println("Creating prime")
		prime, err := genPrime()
		logIfError(err)
		if prime != nil {
			fmt.Printf("created prime: %v\n", prime.String())
		}

		fmt.Println("Creating keypair")
		xpub, err := getXpub()
		logIfError(err)
		// xpub = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11} 	// sample xpub

		userData := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11} // sample userData

		fmt.Println("Generating attestation doc")
		doc, err := attest([]byte{0, 1, 2, 3, 4, 5, 6, 7}, userData, xpub)
		logIfError(err)
		fmt.Printf("doc: %v\n", base64.StdEncoding.EncodeToString(doc))

		time.Sleep(5 * time.Second)
	}
}

// genPrime reads entropy from Nitro Secure Module (https://github.com/hf/nsm)
func genPrime() (*big.Int, error) {
	sess, err := nsm.OpenDefaultSession()
	defer sess.Close()

	if nil != err {
		return nil, err
	}

	return rand.Prime(sess, 2048)
}

func StreamToByte(stream io.Reader) []byte {
	buf := new(bytes.Buffer)
	buf.ReadFrom(stream)
	return buf.Bytes()
}

// getXpub generates a keypair and return its public key as a byte array
func getXpub() ([]byte, error) {
	// get sess
	sess, err := nsm.OpenDefaultSession()
	defer sess.Close()

	if nil != err {
		return nil, err
	}
	// Generate a keypair with ECC
	curve := elliptic.P256()
	xprv, err := ecdsa.GenerateKey(curve, sess)
	fmt.Println("xprv", xprv)
	if err != nil {
		return nil, err
	}
	xpub := xprv.Public()
	fmt.Println("xpub", xpub)

	return nil, nil

	//return xpub.([]byte), nil
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

func logIfError(e error) {
	if e != nil {
		fmt.Printf("error: %v\n", e)
	}
}
