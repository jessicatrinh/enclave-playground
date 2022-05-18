package attestation

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cloudflare/cfssl/revoke"
	"github.com/hf/nitrite"
	"os"
	"time"
)

// VerifyAttestation validates the signature and certificate.
// Pre: Parameter doc is the attestation document as a base64 string. Parameter timeOpt is
// the time for which the attestation document is verified.
// Post: The resulting JSON or error is returned.
func VerifyAttestation(doc string, timeOpt time.Time, n *Nonce) (string, error) {
	docBytes, err := base64.StdEncoding.DecodeString(doc)
	if err != nil {
		// provided attestation document is not encoded as a valid standard Base64 string
		return "", err
	}
	res, err := nitrite.Verify(
		docBytes,
		// If the options specify `Roots` as `nil`, the `DefaultCARoot` will be used.
		nitrite.VerifyOptions{
			CurrentTime: timeOpt,
		})
	resJSON := ""
	if res != nil {
		enc, err := json.Marshal(res.Document)
		if err != nil {
			return "", err
		}
		resJSON = string(enc)
	}
	if err != nil {
		return "", err
	}
	// Check nonce's validity
	if bytes.Compare(res.Document.Nonce, n.Value) != 0 {
		return "", errors.New("mismatched nonce")
	}
	if isExpiredNonce(n) {
		return "", errors.New("expired nonce")
	}
	// Check whether the certificate has been revoked
	err = checkRevokedCert(res.Certificates)
	if err != nil {
		// certificate revocation check error
		return "", err
	}
	return resJSON, nil
}

// PrintJSON prints the JSON legibly to the console.
// Pre: Parameter str is the JSON string.
// Post: None.
func PrintJSON(str string) {
	var prettyJSON bytes.Buffer
	err := json.Indent(&prettyJSON, []byte(str), "", "    ")
	if err != nil {
		fmt.Printf("%s: %v\n", "could not print JSON nicely", err)
		os.Exit(1)
	}
	fmt.Println(prettyJSON.String())
}

// HELPERS:

// checkRevokedCert performs a revocation check on a certificate, which nitrite neglects
// Pre: Parameter certs is a certificate.
// Post: An error or nil is returned.
func checkRevokedCert(certs []*x509.Certificate) error {
	for index, cert := range certs {
		// VerifyCertificate ensures that the certificate passed in hasn't expired and checks the CRL for the server
		if revoked, ok := revoke.VerifyCertificate(cert); !ok {
			return errors.New("warning: soft fail checking revocation")
		} else if revoked {
			return fmt.Errorf("certificate %d was revoked\n", index)
		}
	}
	return nil
}
