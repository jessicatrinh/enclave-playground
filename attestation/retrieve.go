package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"github.com/jessicatrinh/nsm"
	"github.com/jessicatrinh/nsm/request"
)

// GenerateKeypair generates a keypair and return its public key as a byte array.
// Pre: None.
// Post: A public key as a byte array and the private key are returned, or an error is
// returned.
func GenerateKeypair() ([]byte, *ecdsa.PrivateKey, error) {
	// Read entropy from Nitro Secure Module
	sess, err := nsm.OpenDefaultSession()
	defer sess.Close()
	if nil != err {
		return nil, nil, err
	}
	// Generate a keypair with ECC
	curve := elliptic.P256()
	xprv, err := ecdsa.GenerateKey(curve, sess)
	if err != nil {
		return nil, nil, err
	}
	return elliptic.Marshal(curve, xprv.PublicKey.X, xprv.PublicKey.Y), xprv, nil
}

// RetrieveAttestation obtains an attestation document from Nitro Hypervisor
// Pre: Parameters nonce, userData, and publicKey are byte arrays that get supplied to the
// request for the attestation document.
// Post: An attestation document is returned as a byte array, or an error is returned.
func RetrieveAttestation(nonce, userData, publicKey []byte) ([]byte, error) {
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

// LogIfError logs an error to the console.
// Pre: Parameter e is an error.
// Post: None.
func LogIfError(e error) {
	if e != nil {
		fmt.Printf("error: %v\n", e)
	}
}
