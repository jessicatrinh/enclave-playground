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

var path = "errors.txt"


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

// Handling text files (https://www.golangprograms.com/golang-read-write-create-and-delete-text-file.html)

func isError(err error) bool {
	if err != nil {
		fmt.Println(err.Error())
	}

	return (err != nil)
}

// createFile creates (if it doesn't already exist) and opens a file
func createFile() *os.File {
	// check if file exists
	var _, err = os.Stat(path)

	// create file if not exists
	if os.IsNotExist(err) {
		var file, err = os.Create(path)
		if isError(err) {
			return nil
		}
		defer file.Close()
	}

	// Open file using READ & WRITE permission.
	var file2, err2 = os.OpenFile(path, os.O_RDWR, 0644)
	if isError(err2) {
		return nil
	}
	return file2
}

func writeFile(file *os.File, myErr error) {
	// Write some text line-by-line to file
	_, err := file.WriteString(myErr.Error() + "\n")
	if isError(err) {
		return
	}
	// Save file changes
	err = file.Sync()
	if isError(err) {
		return
	}
}

// Pull out into sub-functions:

// getRand returns random number, or writes the error to a file
func getRand(file *os.File) *bytes.Reader {
	// Use NSM's random number generator
	randomInt, err := generateBigPrime()
	// Save to file any error returned by generateBigPrime from nsm interface library
	if err != nil {
		writeFile(file, err)
		fmt.Fprintf(os.Stderr, "error from generateBigPrime(): %v\n", err)
		// TESTING: Prevent main from exiting, even when there is an error in generateBigPrime function
		for {
			fmt.Println("Running attest")
			time.Sleep(3 * time.Second)
		}
		//os.Exit(1)
	}
	return bytes.NewReader(randomInt.Bytes())
	// return rand.Reader // Uncomment for TEST
}

// getXpub generates a keypair and return its public key as a byte array, or writes the
// error to a file
func getXpub(file *os.File, random *bytes.Reader) []byte {
	// Generate a keypair with ECC
	curve := elliptic.P256()
	xprv, err := ecdsa.GenerateKey(curve, random)
	// Save to file any error returned by GenerateKey from ecdsa library
	if err != nil {
		writeFile(file, err)
		fmt.Fprintf(os.Stderr, "error from GenerateKey(): %v\n", err)
		os.Exit(1)
	}
	xpub := xprv.Public()
	return xpub.([]byte)
}


// getAttest retrieves the attestation document, or writes the error to a file
func getDoc(file *os.File, random *bytes.Reader, userData []byte, xpubBytes []byte) {
	att, err := attest(StreamToByte(random), userData, xpubBytes)
	// Save to file any error returned by attest from nsm interface library
	if err != nil {
		writeFile(file, err)
		fmt.Fprintf(os.Stderr, "error from attest(): %v\n", err)
		// TESTING: Prevent main from exiting, even when there is an error in attest function
		for {
			fmt.Println("Running attest")
			time.Sleep(3 * time.Second)
		}
	}
	fmt.Printf("attestation %v %v\n", base64.StdEncoding.EncodeToString(att), err)
}

// MAIN:

func main() {
	file := createFile()
	random := getRand(file)
	xpubBytes := getXpub(file, random)
	userData := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	getDoc(file, random, userData, xpubBytes)
	defer file.Close()
	for {
		fmt.Println("Running attest")
		time.Sleep(3 * time.Second)
	}
}

// TESTING:

//func main() {
//	file := createFile()
//	err1 := errors.New("log test error 1")
//	writeFile(file, err1)
//	err2 := errors.New("log test error 2")
//	writeFile(file, err2)
//	defer file.Close()
//	fmt.Println("Test main finished gracefully.")
//}
