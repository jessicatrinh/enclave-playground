package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"github.com/jessicatrinh/nsm"
	"github.com/jessicatrinh/nsm/request"
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

func main() {
	for {
		fmt.Println("Generating nonce")
		nonce, err := createNonce()
		logIfError(err)
		fmt.Println("Generating keypair")
		xpub, err := getXpub()
		logIfError(err)
		userData := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11} // sample userData
		fmt.Println("Generating attestation doc")
		// TODO: Generate limited lifetime nonce
		doc, err := attest(nonce.value, userData, xpub)
		logIfError(err)
		fmt.Printf("doc: %v\n", base64.StdEncoding.EncodeToString(doc))

		time.Sleep(5 * time.Second)
	}
}

// createNonce generates a limited lifetime nonce
func createNonce() (*Nonce, error) {
	// Read entropy from Nitro Secure Module
	sess, err := nsm.OpenDefaultSession()
	defer sess.Close()
	if err != nil {
		return nil, err
	}
	random, err := rand.Prime(sess, 2048)
	if err != nil {
		return nil, err
	}
	// Set fields in new Nonce object
	return &Nonce{
		value:      random.Bytes(),
		creation:   time.Now(),
		expiration: time.Now().Add(secs),
	}, nil
}

func isExpiredNonce(n *Nonce) bool {
	if time.Now().After(n.expiration) {
		return true
	}
	return false
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
	// GATHER TEST DATA - START (Will remove)
	fmt.Println("xprv:", xprv)
	xprvBytes := xprv.D.Bytes()
	fmt.Println("xprvBytes:", xprvBytes)
	convertedXprv := big.NewInt(0).SetBytes(xprvBytes)
	xpubBytes := elliptic.Marshal(curve, xprv.PublicKey.X, xprv.PublicKey.Y)
	x, y := elliptic.Unmarshal(curve, xpubBytes)
	newXprv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: convertedXprv,
	}
	fmt.Println("newXprv:", newXprv)
	// GATHER TEST DATA - END
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
