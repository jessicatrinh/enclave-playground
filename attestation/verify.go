package attestation

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/cloudflare/cfssl/revoke"
	"github.com/hf/nitrite"
	"github.com/pkg/errors"
	"time"
)

// VerifyAttestation validates the signature and certificate.
// Pre: Parameter doc is the attestation document as a base64 string. Parameter timeOpt is
// the time for which the attestation document is verified.
// Post: The resulting JSON and error/nil is returned.
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

// StringifyAttestation formats the JSON more legibly.
// Pre: Parameter str is the original JSON string.
// Post: A nicely formatted string and error/nil is returned.
func StringifyAttestation(str string) (string, error) {
	var prettyJSON bytes.Buffer
	err := json.Indent(&prettyJSON, []byte(str), "", "    ")
	if err != nil {
		return "", errors.Wrap(err, "could not print JSON nicely")
	}
	return prettyJSON.String(), nil
}

// HELPERS:

// checkRevokedCert performs a revocation check on a certificate, which nitrite neglects
// to do.
// Pre: Parameter certs is a certificate.
// Post: Error/nil is returned.
func checkRevokedCert(certs []*x509.Certificate) error {
	for index, cert := range certs {
		// VerifyCertificate ensures that the certificate passed in hasn't expired and checks the CRL for the server
		if revoked, ok := revoke.VerifyCertificate(cert); !ok {
			return errors.New("warning: soft fail checking revocation")
		} else if revoked {
			return fmt.Errorf("certificate %d was revoked", index)
		}
	}
	return nil
}
