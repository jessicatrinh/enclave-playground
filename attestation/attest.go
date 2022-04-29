package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"github.com/jessicatrinh/nsm"
	"github.com/jessicatrinh/nsm/request"
)

// GetXpub generates a keypair and return its public key as a byte array
func GetXpub() ([]byte, error) {
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
	return elliptic.Marshal(curve, xprv.PublicKey.X, xprv.PublicKey.Y), nil
}

// GetDoc obtains an attestation document from Nitro Hypervisor
func GetDoc(nonce, userData, publicKey []byte) ([]byte, error) {
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

func LogIfError(e error) {
	if e != nil {
		fmt.Printf("error: %v\n", e)
	}
}
