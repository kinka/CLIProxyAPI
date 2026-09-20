package trae

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
)

const (
	headerSize     = 6
	randomBytesLen = 32
	hashSize       = 64
	aesKeySize     = 16
	ivSize         = 16
)

var defaultSaltA = []byte{82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251, 124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203, 84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78, 8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37}
var defaultSaltB = []byte{31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95, 96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239, 160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97, 23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125}
var defaultSaltC = []byte{191, 192, 216, 250, 122, 246, 220, 97, 31, 254, 98, 27, 8, 72, 71, 176, 135, 99, 96, 18, 127, 101, 203, 104, 211, 102, 191, 125, 37, 72, 150, 156, 51, 229, 121, 35, 17, 153, 141, 177, 110, 131, 150, 128, 172, 255, 254, 6, 18, 140, 55, 62, 236, 249, 135, 64, 135, 12, 117, 4, 89, 149, 168, 209}
var defaultSaltD = []byte{246, 204, 26, 232, 232, 70, 129, 109, 223, 146, 169, 242, 23, 241, 105, 145, 50, 196, 165, 42, 254, 120, 3, 54, 244, 207, 209, 85, 53, 6, 138, 106, 175, 148, 31, 204, 186, 186, 165, 182, 87, 142, 49, 10, 39, 110, 26, 154, 86, 56, 173, 125, 18, 64, 198, 225, 99, 99, 83, 82, 191, 134, 76, 170}

type EncType string

const (
	EncTypeAES        EncType = "AES"
	EncTypeAESPrivate EncType = "AES_PRIVATE"
	EncTypeUnknown    EncType = "UNKNOWN"
)

// IsTcEncrypted checks whether the given buffer starts with the "tc" encryption prefix.
func IsTcEncrypted(buf []byte) bool {
	return len(buf) >= headerSize && buf[0] == 0x74 && buf[1] == 0x63
}

// DetectEncType determines the encryption type from the 6-byte header.
func DetectEncType(header []byte) EncType {
	if len(header) < headerSize {
		return EncTypeUnknown
	}
	if header[0] == 0x74 && header[1] == 0x63 && header[2] == 0x05 && header[3] == 0x10 && header[4] == 0x00 && header[5] == 0x00 {
		return EncTypeAES
	}
	if header[0] == 18 && header[1] == 57 && header[2] == 32 && header[3] == 32 && header[4] == 2 && header[5] == 3 {
		return EncTypeAESPrivate
	}
	return EncTypeUnknown
}

func xorSalts(a, b []byte, length int) []byte {
	res := make([]byte, length)
	for i := 0; i < length; i++ {
		res[i] = a[i] ^ b[i]
	}
	return res
}

func sha512Hash(data []byte) []byte {
	h := sha512.Sum512(data)
	return h[:]
}

// DeriveKeyAndIV generates the AES-128 key and IV from 32 random bytes and encryption type.
func DeriveKeyAndIV(randomBytes []byte, encType EncType) ([]byte, []byte) {
	var salt []byte
	if encType == EncTypeAESPrivate {
		salt = xorSalts(defaultSaltC, defaultSaltD, hashSize)
	} else {
		salt = xorSalts(defaultSaltA, defaultSaltB, hashSize)
	}

	hashOfRandom := sha512Hash(randomBytes)
	combined := append(hashOfRandom, salt...)
	finalHash := sha512Hash(combined)

	aesKey := finalHash[:aesKeySize]
	iv := finalHash[aesKeySize : aesKeySize+ivSize]
	return aesKey, iv
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("pkcs7: unpad empty data")
	}
	padLen := int(data[length-1])
	if padLen == 0 || padLen > length {
		return nil, errors.New("pkcs7: invalid padding size")
	}
	for i := 0; i < padLen; i++ {
		if data[length-1-i] != byte(padLen) {
			return nil, errors.New("pkcs7: invalid padding byte")
		}
	}
	return data[:length-padLen], nil
}

// DecryptTcBuffer decrypts a "tc" formatted binary payload.
func DecryptTcBuffer(encryptedBuffer []byte) ([]byte, error) {
	if len(encryptedBuffer) < headerSize+randomBytesLen+hashSize+16 {
		return nil, fmt.Errorf("buffer too short: %d", len(encryptedBuffer))
	}

	header := encryptedBuffer[:headerSize]
	encType := DetectEncType(header)
	if encType == EncTypeUnknown {
		return nil, fmt.Errorf("unknown encryption type: %x", header)
	}

	randomBytes := encryptedBuffer[headerSize : headerSize+randomBytesLen]
	encryptedData := encryptedBuffer[headerSize+randomBytesLen:]

	aesKey, iv := DeriveKeyAndIV(randomBytes, encType)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("aes cipher creation failed: %w", err)
	}

	if len(encryptedData)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("encrypted data length %d not a multiple of block size", len(encryptedData))
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	decryptedPadded := make([]byte, len(encryptedData))
	mode.CryptBlocks(decryptedPadded, encryptedData)

	decrypted, err := pkcs7Unpad(decryptedPadded)
	if err != nil {
		return nil, fmt.Errorf("aes unpad failed: %w", err)
	}

	if len(decrypted) < hashSize {
		return nil, fmt.Errorf("decrypted data too short: %d", len(decrypted))
	}

	storedHash := decrypted[:hashSize]
	plaintext := decrypted[hashSize:]
	computedHash := sha512Hash(plaintext)

	if !bytes.Equal(storedHash, computedHash) {
		return nil, errors.New("hash verification failed - data may be corrupted or wrong key")
	}

	return plaintext, nil
}

// DecryptStorageValue decodes a base64 encoded "tc" string and decrypts it.
func DecryptStorageValue(base64Value string) ([]byte, error) {
	buf, err := base64.StdEncoding.DecodeString(base64Value)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed: %w", err)
	}
	return DecryptTcBuffer(buf)
}

// HashDeviceID replicates Trae's JS 32-bit integer string hash for telemetry.machineId.
func HashDeviceID(machineID string) string {
	if machineID == "" {
		return "0000000000000000000"
	}
	var hash int32
	for i := 0; i < len(machineID); i++ {
		char := int32(machineID[i])
		hash = ((hash << 5) - hash) + char
	}
	absVal := int64(hash)
	if absVal < 0 {
		absVal = -absVal
	}
	return fmt.Sprintf("%019d", absVal)
}
