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

// checkRevokedCert checks for revoked certificates (revocation checks are NOT performed by nitrite)
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

// VerifyAttestation validates the signature and certificate
func VerifyAttestation(doc string, timeOpt time.Time) (string, error) {
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
	err = checkRevokedCert(res.Certificates)
	if err != nil {
		// certificate revocation check error
		return "", err
	}
	return resJSON, nil
}

// HELPERS:

func ExitIfError(msg string, e error) {
	if e != nil {
		fmt.Printf("%s: %v\n", msg, e)
		os.Exit(1)
	}
}

func PrintJSON(str string) {
	var prettyJSON bytes.Buffer
	err := json.Indent(&prettyJSON, []byte(str), "", "    ")
	ExitIfError("could not print JSON nicely", err)
	fmt.Println(prettyJSON.String())
}
