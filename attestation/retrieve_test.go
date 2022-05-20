package attestation

import (
	"errors"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		xpubBytes, xprv, err := GenerateKeypair()
		require.NoError(t, err)
		require.NotEmpty(t, xpubBytes)
		require.NotEmpty(t, xprv)
	})
}

func TestRetrieveAttestation(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		doc, err := RetrieveAttestation([]byte{40, 187, 79, 105, 38, 217, 50, 149}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}, []byte{4, 116, 1, 121, 173, 200, 146, 167, 74, 243, 10, 193, 79, 65, 151, 206, 34, 146, 41, 255, 81, 101, 83, 8, 47, 113, 84, 37, 53, 194, 255, 185, 44, 245, 118, 124, 97, 164, 162, 196, 166, 149, 87, 11, 254, 121, 75, 231, 61, 75, 23, 55, 164, 247, 3, 138, 143, 73, 75, 145, 1, 102, 72, 150, 86})
		require.NoError(t, err)
		require.NotEmpty(t, doc)
	})
}

func TestLogIfError(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ExampleLogIfError()
	})
}

func ExampleLogIfError() {
	LogIfError(errors.New("sample error"))
	// Output: error: sample error
}
