package attestation

import (
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestVerify(t *testing.T) {
	t.Run("revoked certificate", func(t *testing.T) {
		doc := "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"
		resJSON, err := VerifyAttestation(doc, time.Date(2022, 04, 28, 01, 50, 57, 651387237, time.UTC))
		require.Errorf(t, err, "certificate 0 was revoked")
		require.Empty(t, resJSON)
	})

	t.Run("expired certificate", func(t *testing.T) {
		doc := "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"
		resJSON, err := VerifyAttestation(doc, time.Now())
		require.Errorf(t, err, "x509: certificate has expired or is not yet valid: current time "+(time.Now()).String()+" is after 2022-04-27T23:24:27Z")
		require.Empty(t, resJSON)
	})

	t.Run("certificate not yet valid", func(t *testing.T) {
		doc := "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"
		resJSON, err := VerifyAttestation(doc, time.Date(2009, 01, 03, 20, 9, 1, 123456789, time.UTC))
		require.Errorf(t, err, "x509: certificate has expired or is not yet valid: current time 2009-01-03T20:09:01Z is before 2022-04-27T23:51:54Z")
		require.Empty(t, resJSON)
	})

	t.Run("invalid doc", func(t *testing.T) {
		doc := "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"
		resJSON, err := VerifyAttestation(doc, time.Now())
		require.Errorf(t, err, "Bad attestation document")
		require.Empty(t, resJSON)
	})

	t.Run("non base64 doc", func(t *testing.T) {
		doc := "base64"
		resJSON, err := VerifyAttestation(doc, time.Now())
		require.Errorf(t, err, "illegal base64 data at input byte 4")
		require.Empty(t, resJSON)
	})

	// TODO: Fix unit test for successful case
	t.Run("valid attestation doc", func(t *testing.T) {
		doc := "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"
		resJSON, err := VerifyAttestation(doc, time.Now())
		require.NoError(t, err)
		require.NotEmpty(t, resJSON)
	})
}

// SAMPLE ATTESTATION DOCUMENT VERIFICATION CONSOLE LOG:
//{
//"module_id": "i-014a5e7aa70a39862-enc0180729cc928c5ef",
//"timestamp": 1651190320249,
//"digest": "SHA384",
//"pcrs": {
//"0": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
//"1": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
//"10": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
//"11": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
//"12": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
//"13": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
//"14": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
//"15": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
//"2": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
//"3": "fR/audK3srh8yawGEFAIDL2wfsZuwadM4miGW6X+DWa4iy31ap8gtU1g7Ff/IK4h",
//"4": "QdDOmnZHVj71mtFioU4iQxv4ABaJZnKI8YYcHurVlnCHL5ftIffKEH5wb6OOggYg",
//"5": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
//"6": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
//"7": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
//"8": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
//"9": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
//},
//"certificate": "MIICejCCAgGgAwIBAgIQAYBynMkoxe8AAAAAYmsqMDAKBggqhkjOPQQDAzCBjjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xEDAOBgNVBAcMB1NlYXR0bGUxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMTkwNwYDVQQDDDBpLTAxNGE1ZTdhYTcwYTM5ODYyLnVzLWVhc3QtMS5hd3Mubml0cm8tZW5jbGF2ZXMwHhcNMjIwNDI4MjM1ODM3WhcNMjIwNDI5MDI1ODQwWjCBkzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xEDAOBgNVBAcMB1NlYXR0bGUxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMT4wPAYDVQQDDDVpLTAxNGE1ZTdhYTcwYTM5ODYyLWVuYzAxODA3MjljYzkyOGM1ZWYudXMtZWFzdC0xLmF3czB2MBAGByqGSM49AgEGBSuBBAAiA2IABA+tmXQqhHFoFcx0WskzHLxrK7Eun0HYIx35lp9XMa/+6xl/DleBDcmLelwjsdC/Fq32d3XeAlNZL6+TNiaKIYOwv26VUnYQdczmEuL6jWCiR4TCpgVs9XClc75PaF9zQKMdMBswDAYDVR0TAQH/BAIwADALBgNVHQ8EBAMCBsAwCgYIKoZIzj0EAwMDZwAwZAIwCoXDlbiHWXt64dUMsJOZcUJ1NoRKCaCgkyMjbXhkkxqeh8KiPgvQfsuoTropbwEWAjBJ0DhWFaS9X1rRKPsjB1C6k7lO3m/0KsKSpTknOR1AvBiuJqZr0d1mI2U6pobdVZ4=",
//"cabundle": [
//"MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTELMAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYDVQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQLDANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEGBSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZEh8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkFR+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYCMQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPWrfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6NIwLz3/Y=",
//"MIICvjCCAkSgAwIBAgIQHgRr5QtlylZoMymrwIAbxDAKBggqhkjOPQQDAzBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQLDANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczAeFw0yMjA0MjcwNTA3NDZaFw0yMjA1MTcwNjA3NDZaMGQxCzAJBgNVBAYTAlVTMQ8wDQYDVQQKDAZBbWF6b24xDDAKBgNVBAsMA0FXUzE2MDQGA1UEAwwtZmYzZTAzNWIzZTdjYTY3Yi51cy1lYXN0LTEuYXdzLm5pdHJvLWVuY2xhdmVzMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEihFJtTGK6sR6/yNv6/m2nX7jzIK3KlaN8Om6wacg6LM8ghBgjAEeNBCRXT1uVNbqGRbNE8O/XxuGujMD6cmMnmQ9Pr2/eVYGBmVAMSXQo7jo03rWSzwsXobODcnu0KHHo4HVMIHSMBIGA1UdEwEB/wQIMAYBAf8CAQIwHwYDVR0jBBgwFoAUkCW1DdkFR+eWw5b6cp3PmanfS5YwHQYDVR0OBBYEFA+Qy2+/jAgznQ2Qdg79kRaR3GJDMA4GA1UdDwEB/wQEAwIBhjBsBgNVHR8EZTBjMGGgX6BdhltodHRwOi8vYXdzLW5pdHJvLWVuY2xhdmVzLWNybC5zMy5hbWF6b25hd3MuY29tL2NybC9hYjQ5NjBjYy03ZDYzLTQyYmQtOWU5Zi01OTMzOGNiNjdmODQuY3JsMAoGCCqGSM49BAMDA2gAMGUCMCXV4IkqhkACNwjm3gdKo7Qclc6ZaEhQIhrr3lwvRONOltA3TfHVO/uKthgNOtX0XQIxAJAn/Tvg64PgCGtOk1P/Qwfh2nYAi/EFtRpZvzxrQEOnM0GN8UT37ltZlcOH/NreWw==",
//"MIIDFTCCApugAwIBAgIRAKeKYnL9z2VySCe6Z/Hk5qcwCgYIKoZIzj0EAwMwZDELMAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMTYwNAYDVQQDDC1mZjNlMDM1YjNlN2NhNjdiLnVzLWVhc3QtMS5hd3Mubml0cm8tZW5jbGF2ZXMwHhcNMjIwNDI4MTY1NDIwWhcNMjIwNTA0MDk1NDE5WjCBiTE8MDoGA1UEAwwzYmVhNTllNjY2ZWM1YjhlMC56b25hbC51cy1lYXN0LTEuYXdzLm5pdHJvLWVuY2xhdmVzMQwwCgYDVQQLDANBV1MxDzANBgNVBAoMBkFtYXpvbjELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAldBMRAwDgYDVQQHDAdTZWF0dGxlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEN30/uIiUYNaNmz5LmHcU/ymVXMcXRW768Ry365iSELBfxaKrLrlW6Lt8hQXCjXjNOoCkp4opmurcbYrFdaGifD3gK8gsdnLXE+6A0BEBZcmoaE8ggcLgZgzaVG1bkO7yo4HqMIHnMBIGA1UdEwEB/wQIMAYBAf8CAQEwHwYDVR0jBBgwFoAUD5DLb7+MCDOdDZB2Dv2RFpHcYkMwHQYDVR0OBBYEFJF3d3Ws1sFWMh7bn1cCPY7IqwnbMA4GA1UdDwEB/wQEAwIBhjCBgAYDVR0fBHkwdzB1oHOgcYZvaHR0cDovL2NybC11cy1lYXN0LTEtYXdzLW5pdHJvLWVuY2xhdmVzLnMzLnVzLWVhc3QtMS5hbWF6b25hd3MuY29tL2NybC9lZTExZGZmZC1lZTlmLTRkMjYtYmFmOC0zNWQwYzZiMDc2MjcuY3JsMAoGCCqGSM49BAMDA2gAMGUCMDwu36CpQQ7AocX95BHu96ja5yt0wAHdVHuHGMkdjS55PV3jR0SZa13PckC0L4rRkwIxAL6LWoIbeYFVYmvm2Ayt1C4LsmSlveKqEqJKBJOKXKXGlVLDtVFRPRCvWTs/1d7hcA==",
//"MIICfjCCAgSgAwIBAgIULXWJ5k+BlhjydUGCxsrPLMhsPC8wCgYIKoZIzj0EAwMwgYkxPDA6BgNVBAMMM2JlYTU5ZTY2NmVjNWI4ZTAuem9uYWwudXMtZWFzdC0xLmF3cy5uaXRyby1lbmNsYXZlczEMMAoGA1UECwwDQVdTMQ8wDQYDVQQKDAZBbWF6b24xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJXQTEQMA4GA1UEBwwHU2VhdHRsZTAeFw0yMjA0MjgyMDQyMDBaFw0yMjA0MjkyMDQyMDBaMIGOMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjEQMA4GA1UEBwwHU2VhdHRsZTEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQLDANBV1MxOTA3BgNVBAMMMGktMDE0YTVlN2FhNzBhMzk4NjIudXMtZWFzdC0xLmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEGBSuBBAAiA2IABM5Jm0mWkGzYHlFQUxayh2Z0VrCfklAzcJTIcP/vmSy5SYE1UBhTmhfx+vm6ht2WYrMzuvTiTyy/xXP+M1AiNFlV9xqiHUVOfcQnZaM9d5goLSI9Uchg0gAjYnTM/4kzzKMmMCQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAgQwCgYIKoZIzj0EAwMDaAAwZQIxAJjwbW80xWIwrH/pii/YezmU8pgTffRGbZHQnXLJHozQocOcQqRYxav+ViW0iZjHpQIwSDTUt8q1xLY5xiAGhodxBhMTaPwtHSAjtzOYl6hXjhEg8jvmUl3mX/+dpiN0no93"
//],
//"public_key": "BKiC1i9cSNABZs5VEi5PkxiiqVA7BOPriVw4OQdk8n1z1oVdFmfusc6SO1E7mb6FoEZO4ZpQLNHh5rwW/9RDeOM=",
//"user_data": "AAECAwQFBgcICQoL",
//"nonce": "MiisRs38DMw="
//}
