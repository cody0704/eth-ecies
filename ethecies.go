package ethecies

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"
	"log"

	"github.com/btcsuite/btcutil/base58"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
)

type Crypt struct {
	EthHexKey string
}

// LoadKey load eth hex key.
func LoadKey(ethHexKey string) Crypt {
	var crypt Crypt
	crypt = Crypt{}
	crypt.EthHexKey = ethHexKey

	return crypt
}

// Encrypt uses the eth hex key to encrypt the message
func (c Crypt) Encrypt(msg string) (ciphertext, signature string, err error) {
	ethKey, err := crypto.HexToECDSA(c.EthHexKey)
	if err != nil {
		return "", "", err
	}

	eciesPri := ecies.ImportECDSA(ethKey)

	ciphertext = encrypt(msg, &eciesPri.PublicKey)

	hash := crypto.Keccak256Hash([]byte(ciphertext))
	signature = sign(hash, ethKey)

	return ciphertext, signature, nil
}

// Decrypt uses the eth hex key to dencrypt the ciphertext
func (c Crypt) Decrypt(ciphertext, signature string) (string, error) {
	ethKey, _ := crypto.HexToECDSA(c.EthHexKey)
	ethPubKey := ethKey.Public()
	ethPubKeyECDSA, ok := ethPubKey.(*ecdsa.PublicKey)
	if !ok {
		fmt.Println("error casting public key to ECDSA")
	}
	ethPubKeyBytes := crypto.FromECDSAPub(ethPubKeyECDSA)

	hash := crypto.Keccak256Hash([]byte(ciphertext))
	ct := base58.Decode(ciphertext)
	sig := base58.Decode(signature)

	if signVerify(hash, sig, ethPubKeyBytes) {
		eciesPri := ecies.ImportECDSA(ethKey)
		plaintext := decrypt(ct, eciesPri)
		return plaintext, nil
	}

	return "", errors.New("Signature verification failed")
}

func encrypt(msg string, pub *ecies.PublicKey) string {
	data, err := ecies.Encrypt(rand.Reader, pub, []byte(msg), nil, nil)
	if err != nil {
		log.Fatal(err)
	}

	ciphertext := base58.Encode(data)

	return ciphertext
}

func decrypt(ct []byte, pri *ecies.PrivateKey) string {
	data, err := pri.Decrypt(ct, nil, nil)
	if err != nil {
		log.Fatal(err)
	}

	plaintext := string(data)

	return plaintext
}

func sign(hash common.Hash, prv *ecdsa.PrivateKey) (sig58 string) {
	sig, err := crypto.Sign(hash.Bytes(), prv)
	if err != nil {
		log.Fatal(err)
	}
	sig58 = base58.Encode(sig)
	return
}

func signVerify(hash common.Hash, sig []byte, pub []byte) bool {
	sigPublicKey, err := crypto.Ecrecover(hash.Bytes(), sig)
	if err != nil {
		fmt.Println(err)
	}

	if !bytes.Equal(sigPublicKey, pub) {
		return false
	}

	sigPublicKeyECDSA, err := crypto.SigToPub(hash.Bytes(), sig)
	if err != nil {
		log.Fatal(err)
	}

	sigPublicKeyBytes := crypto.FromECDSAPub(sigPublicKeyECDSA)

	if !bytes.Equal(sigPublicKeyBytes, pub) {
		return false
	}

	return crypto.VerifySignature(pub, hash.Bytes(), sig[:len(sig)-1])
}
