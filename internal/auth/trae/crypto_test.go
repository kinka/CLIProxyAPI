package trae

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - (len(data) % blockSize)
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, padding...)
}

func encryptTcBufferForTest(plaintext []byte, encType EncType) ([]byte, error) {
	var header []byte
	if encType == EncTypeAESPrivate {
		header = []byte{18, 57, 32, 32, 2, 3}
	} else {
		header = []byte{0x74, 0x63, 0x05, 0x10, 0x00, 0x00}
	}

	randomBytes := make([]byte, randomBytesLen)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, err
	}

	aesKey, iv := DeriveKeyAndIV(randomBytes, encType)
	computedHash := sha512Hash(plaintext)
	dataToEncrypt := append(computedHash, plaintext...)
	paddedData := pkcs7Pad(dataToEncrypt, aes.BlockSize)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	encryptedData := make([]byte, len(paddedData))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(encryptedData, paddedData)

	res := append(header, randomBytes...)
	res = append(res, encryptedData...)
	return res, nil
}

func TestDecryptTcBuffer(t *testing.T) {
	testJSON := `{"token":"jwt-test-token-12345","userId":"u-1234","expiredAt":"2026-10-01T00:00:00Z"}`

	// Test AES encryption type
	encBuf, err := encryptTcBufferForTest([]byte(testJSON), EncTypeAES)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	if !IsTcEncrypted(encBuf) {
		t.Fatalf("IsTcEncrypted should be true")
	}

	decrypted, err := DecryptTcBuffer(encBuf)
	if err != nil {
		t.Fatalf("DecryptTcBuffer failed: %v", err)
	}

	if string(decrypted) != testJSON {
		t.Fatalf("expected %s, got %s", testJSON, string(decrypted))
	}

	// Test Base64 decoding wrapper
	b64 := base64.StdEncoding.EncodeToString(encBuf)
	decB64, err := DecryptStorageValue(b64)
	if err != nil {
		t.Fatalf("DecryptStorageValue failed: %v", err)
	}
	if string(decB64) != testJSON {
		t.Fatalf("expected %s, got %s", testJSON, string(decB64))
	}
}

func TestHashDeviceID(t *testing.T) {
	emptyHash := HashDeviceID("")
	if emptyHash != "0000000000000000000" {
		t.Fatalf("expected 19 zeros, got %s", emptyHash)
	}

	h1 := HashDeviceID("abc-123-machine-id")
	if len(h1) != 19 {
		t.Fatalf("expected length 19, got %d (%s)", len(h1), h1)
	}
}
