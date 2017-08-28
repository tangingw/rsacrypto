package RSAcrypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/gob"
	"encoding/pem"
	"fmt"
	"hash"
	"io"
	"os"
)

// RSAKeyPair is the keypair struct that
//contains both Public Key and Private Key
type RSAKeyPair struct {
	PublicKey  *rsa.PublicKey  //RSA Public Key
	PrivateKey *rsa.PrivateKey //RSA Private Key
}

func GenerateRSAKey(bitSize int) RSAKeyPair {

	key, keyErr := rsa.GenerateKey(rand.Reader, bitSize)

	checkErr(keyErr)

	return RSAKeyPair{&key.PublicKey, key}
}

func (r *RSAKeyPair) EncryptOAEP(hash hash.Hash, plainMsg, label []byte) []byte {

	ciphertext, cipherErr := rsa.EncryptOAEP(
		hash,
		rand.Reader,
		r.PublicKey,
		plainMsg,
		label,
	)

	checkErr(cipherErr)

	return ciphertext
}

func (r *RSAKeyPair) DecryptOAEP(hash hash.Hash, encryptedMsg, label []byte) []byte {

	recoverMessage, recoverErr := rsa.DecryptOAEP(
		hash,
		rand.Reader,
		r.PrivateKey,
		encryptedMsg,
		label,
	)

	checkErr(recoverErr)

	return recoverMessage
}

func ReadFile(filename string) []byte {

	file, err := os.OpenFile(filename, os.O_RDONLY, 0400)

	if err != nil {

		fmt.Printf("file: %s not found!\n", filename)
		fmt.Printf("Please generate the new pubkey.pem File\n")
		os.Exit(1)
	}

	defer file.Close()

	buf := make([]byte, 64*1024)

	for {
		n, readErr := file.Read(buf)

		if readErr != io.EOF {

			checkErr(readErr)
		}

		if n == 0 {
			break
		}
	}

	return buf
}

/**
Reference from:
https://gist.github.com/sdorra/1c95de8cb80da31610d2ad767cd6f251
**/
func SavePEMKey(fileName string, key *rsa.PrivateKey) {

	outFile, outFileErr := os.Create(fileName)

	checkErr(outFileErr)

	defer outFile.Close()

	privateKey := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	pemErr := pem.Encode(outFile, privateKey)

	checkErr(pemErr)
}

func RetrievePEMKey(filename string) *rsa.PrivateKey {

	buf := ReadFile(filename)
	block, _ := pem.Decode(buf)

	if block == nil || block.Type != "PRIVATE KEY" {
		panic("failed to decode PEM block containing private key")
	}

	privateKey, privErr := x509.ParsePKCS1PrivateKey(block.Bytes)

	checkErr(privErr)

	return privateKey
}

func SavePublicPEMKey(fileName string, pubkey *rsa.PublicKey) {

	asn1Bytes, bytesErr := asn1.Marshal(*pubkey)

	checkErr(bytesErr)

	var pemkey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}

	pemfile, pemErr := os.Create(fileName)

	checkErr(pemErr)

	defer pemfile.Close()

	encErr := pem.Encode(pemfile, pemkey)

	checkErr(encErr)
}

func RetrievePEMPubKey(filename string) *rsa.PublicKey {

	buf := ReadFile(filename)

	block, _ := pem.Decode(buf)

	if block == nil || block.Type != "PUBLIC KEY" {
		panic("failed to decode PEM block containing public key")
	}

	publicKey := &rsa.PublicKey{}
	_, pubErr := asn1.Unmarshal(block.Bytes, publicKey)

	checkErr(pubErr)

	return publicKey
}

func SaveGobKey(filename string, key interface{}) {

	outputFile, outFileErr := os.Create(filename)

	checkErr(outFileErr)

	defer outputFile.Close()

	gobEnconder := gob.NewEncoder(outputFile)
	encodeErr := gobEnconder.Encode(key)

	checkErr(encodeErr)
}

func RetrieveGobKey(filename string, keyType interface{}) interface{} {

	file, err := os.OpenFile(filename, os.O_RDONLY, 0400)

	if err != nil {
		fmt.Printf("file: %s not found!\n", filename)
		fmt.Printf("Please generate the new key File\n")
		os.Exit(1)
	}

	defer file.Close()

	gobDecoder := gob.NewDecoder(file)
	gobError := gobDecoder.Decode(keyType)

	checkErr(gobError)

	return keyType
}

func checkErr(err error) {

	if err != nil {
		panic(err)
	}
}
