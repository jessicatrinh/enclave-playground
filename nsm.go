package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"github.com/jessicatrinh/nsm"
	"github.com/jessicatrinh/nsm/request"
	"time"
)

func main() {
	for {
		fmt.Println("Creating keypair")
		xpub, err := getXpub()
		logIfError(err)
		userData := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11} // sample userData
		fmt.Println("Generating attestation doc")
		doc, err := attest([]byte{0, 1, 2, 3, 4, 5, 6, 7}, userData, xpub)
		logIfError(err)
		fmt.Printf("doc: %v\n", base64.StdEncoding.EncodeToString(doc))

		time.Sleep(5 * time.Second)
	}
}

// getXpub generates a keypair and return its public key as a byte array
func getXpub() ([]byte, error) {
	// Read entropy from Nitro Secure Module
	sess, err := nsm.OpenDefaultSession()
	defer sess.Close()
	if nil != err {
		return nil, err
	}
	// Generate a keypair with ECC
	curve := elliptic.P256()
	xprv, err := ecdsa.GenerateKey(curve, sess)
	if err != nil {
		return nil, err
	}
	fmt.Println("xprv original:", xprv) // TESTING
	xprvBytes, err := encodeXpriv(xprv)
	if err != nil {
		return nil, err
	}
	fmt.Println("xprvBytes:", xprvBytes) // TESTING
	xprvDecoded, err := decodeXpriv(xprvBytes)
	if err != nil {
		return nil, err
	}
	fmt.Println("xprvDecoded", xprvDecoded)                // TESTING
	fmt.Println("xprv==xprvDecoded?", xprv == xprvDecoded) // TESTING
	return elliptic.Marshal(curve, xprv.PublicKey.X, xprv.PublicKey.Y), nil
}

// attest obtain an attestation document from Nitro Hypervisor
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

// HELPERS:

func logIfError(e error) {
	if e != nil {
		fmt.Printf("error: %v\n", e)
	}
}

// encodeXpriv encodes a *PrivateKey as a byte sequence
func encodeXpriv(xprv *ecdsa.PrivateKey) ([]byte, error) {
	var buf bytes.Buffer
	err := gob.NewEncoder(&buf).Encode(xprv)
	return buf.Bytes(), err
}

// decodeXpriv decodes a *PrivateKey object that was encoded
func decodeXpriv(b []byte) (*ecdsa.PrivateKey, error) {
	xprv := &ecdsa.PrivateKey{}
	err := gob.NewDecoder(bytes.NewBuffer(b)).Decode(xprv)
	return xprv, err
}
