package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/jessicatrinh/nsm/request"
	"math/big"
	"time"

	"github.com/jessicatrinh/nsm"
)

func main() {
	for {
		fmt.Println("Creating prime")
		prime, err := genPrime()
		logIfError(err)
		if prime != nil {
			fmt.Printf("created prime: %v\n", prime.String())
		}

		fmt.Println("Generating attestation doc")
		doc, err := attest([]byte{0, 1, 2, 3, 4, 5, 6, 7}, nil, nil)
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
