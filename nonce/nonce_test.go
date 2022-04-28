package nonce

import (
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestNonce(t *testing.T) {
	nonce, err := CreateNonce()
	require.NoError(t, err)

	t.Run("unexpired nonce", func(t *testing.T) {
		expired := isExpiredNonce(nonce)
		require.False(t, expired)
	})

	t.Run("expired nonce", func(t *testing.T) {
		time.Sleep(secs)
		expired := isExpiredNonce(nonce)
		require.True(t, expired)
	})
}
