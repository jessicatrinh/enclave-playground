package attestation

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestGenerateKeyPair(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		xpubBytes, xprv, err := GenerateKeypair()
		require.NoError(t, err)
		require.NotEmpty(t, xpubBytes)
		fmt.Println("xpubBytes:", xpubBytes) // temp, use in TestRetrieveAttestation
		require.NotEmpty(t, xprv)
	})
}

func TestRetrieveAttestation(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		nonce, err := CreateNonce(time.Second * 1)
		require.NoError(t, err)
		xpubBytes, _, err := GenerateKeypair()
		require.NoError(t, err)
		userData := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
		doc, err := RetrieveAttestation(nonce.Value, userData, xpubBytes)
		require.NoError(t, err)
		require.NotEmpty(t, doc)
	})
}
