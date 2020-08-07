package utils

import (
	"crypto/rand"
	"io"
)


func CreateNonce() ([]byte, error) {
	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	//Debug("Nonce:", hex.EncodeToString(nonce))
	return nonce,nil
}



