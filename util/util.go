package echutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"slices"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/cryptobyte"
)

const (
	AEAD_AES_128_GCM      = 0x0001
	AEAD_AES_256_GCM      = 0x0002
	AEAD_ChaCha20Poly1305 = 0x0003

	extensionEncryptedClientHello uint16 = 0xfe0d
	DHKEM_X25519_HKDF_SHA256             = 0x0020
	KDF_HKDF_SHA256                      = 0x0001
)

var aesGCMNew = func(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

var supportedAEADs = map[uint16]struct {
	keySize   int
	nonceSize int
	aead      func([]byte) (cipher.AEAD, error)
}{
	// RFC 9180, Section 7.3
	AEAD_AES_128_GCM:      {keySize: 16, nonceSize: 12, aead: aesGCMNew},
	AEAD_AES_256_GCM:      {keySize: 32, nonceSize: 12, aead: aesGCMNew},
	AEAD_ChaCha20Poly1305: {keySize: chacha20poly1305.KeySize, nonceSize: chacha20poly1305.NonceSize, aead: chacha20poly1305.New},
}

// Generates a serialized Encrypted Client Hello (ECH) configuration for a given domain
func GetECHConfig(privateKey *ecdh.PrivateKey, domain string) ([]byte, error) {
	/// generate the echconfig
	var sortedSupportedAEADs []uint16
	for aeadID := range supportedAEADs {
		sortedSupportedAEADs = append(sortedSupportedAEADs, aeadID)
	}
	slices.Sort(sortedSupportedAEADs)

	marshalECHConfig := func(id uint8, pubKey []byte, publicName string, maxNameLen uint8) ([]byte, error) {
		builder := cryptobyte.NewBuilder(nil)
		builder.AddUint16(extensionEncryptedClientHello)
		builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
			builder.AddUint8(id)
			builder.AddUint16(DHKEM_X25519_HKDF_SHA256) // The only DHKEM we support
			builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
				builder.AddBytes(pubKey)
			})
			builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
				for _, aeadID := range sortedSupportedAEADs {
					builder.AddUint16(KDF_HKDF_SHA256) // The only KDF we support
					builder.AddUint16(aeadID)
				}
			})
			builder.AddUint8(maxNameLen)
			builder.AddUint8LengthPrefixed(func(builder *cryptobyte.Builder) {
				builder.AddBytes([]byte(publicName))
			})
			builder.AddUint16(0) // extensions
		})

		return builder.Bytes()
	}

	return marshalECHConfig(123, privateKey.PublicKey().Bytes(), domain, 32)
}

// Generates a serialized list of Encrypted Client Hello (ECH) configuration for a set of domains
func GetECHConfigList(privateKey *ecdh.PrivateKey, domains []string) ([]byte, error) {

	builder := cryptobyte.NewBuilder(nil)
	var configs [][]byte
	for _, d := range domains {
		echConfig, err := GetECHConfig(privateKey, d)
		if err != nil {
			return nil, err
		}
		configs = append(configs, echConfig)
	}

	builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
		for _, b := range configs {
			builder.AddBytes(b)
		}
	})

	return builder.Bytes()
}
