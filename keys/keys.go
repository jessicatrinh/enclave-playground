package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"
)

// Original xprv: &{{{0xc0000b1580} 54834249719739120581359735047975308973185460557924444130956824360389423407499 99537678059495310831427257493611743876710830625779191793284433849264947332781} 56661850738874315015914794399618040457860594442696112725244829705319968626702}

var (
	curve     = elliptic.P256()
	xprvBytes = []byte{125, 69, 120, 148, 179, 28, 104, 76, 218, 252, 117, 242, 242, 89, 207, 219, 161, 5, 202, 182, 55, 131, 177, 221, 41, 171, 238, 166, 103, 107, 88, 14}
	xpubBytes = []byte{4, 121, 59, 21, 227, 73, 177, 109, 134, 75, 247, 214, 143, 37, 81, 160, 22, 203, 2, 86, 206, 217, 129, 18, 52, 130, 181, 40, 118, 21, 44, 33, 139, 220, 16, 84, 76, 213, 145, 4, 5, 182, 103, 235, 0, 1, 176, 191, 194, 252, 13, 16, 104, 156, 255, 65, 217, 6, 135, 51, 43, 66, 208, 6, 173}
)

func main() {
	xprv := getKeypair()
	fmt.Println("xprv:", xprv)
}

func getKeypair() *ecdsa.PrivateKey {
	x, y := elliptic.Unmarshal(curve, xpubBytes)
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: big.NewInt(0).SetBytes(xprvBytes),
	}
}
