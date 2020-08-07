// Copyright (c) 2020, Yanbin (Henry) Zheng <ybzheng@gmail.com>
// All rights reserved.
//
// Use of this source code is governed by a AGPLv3 license that can be
// found in the LICENSE file.

package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"golang.org/x/crypto/scrypt"
	"io/ioutil"
	"path/filepath"
)

//https://crypto.stackexchange.com/questions/42412/gcm-padding-or-not
//padding is not required for AES-GCM

// Encrypt encrypts data using 256-bit AES-GCM.  This both hides the content of
// the data and provides a check that it hasn't been altered. Output takes the
// form nonce|ciphertext|tag where '|' indicates concatenation.
func Encrypt(plaintext []byte, key *[32]byte) (ciphertext []byte, err error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if nonce, err := CreateNonce(); err != nil {
		return nil, err
	} else {
		return gcm.Seal(nonce, nonce, plaintext, nil), nil
	}
}

// Decrypt decrypts data using 256-bit AES-GCM.  This both hides the content of
// the data and provides a check that it hasn't been altered. Expects input
// form nonce|ciphertext|tag where '|' indicates concatenation.
func Decrypt(ciphertext []byte, key *[32]byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("malformed ciphertext")
	}

	return gcm.Open(nil,
		ciphertext[:gcm.NonceSize()],
		ciphertext[gcm.NonceSize():],
		nil,
	)
}

type Params struct {
	N       int // CPU/memory cost parameter (logN)
	R       int // block size parameter (octets)
	P       int // parallelisation parameter (positive int)
	SaltLen int // bytes to use as salt (octets)
	DKLen   int // length of the derived key (octets)
}

// DefaultParams provides sensible default inputs into the scrypt function
// for interactive use (i.e. web applications).
// These defaults will consume approximately 16MB of memory (128 * r * N).
// The default key length is 256 bits.
var DefaultParams = Params{N: 16384, R: 8, P: 1, SaltLen: 16, DKLen: 32}

func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// err == nil only if len(b) == n
	if err != nil {
		return nil, err
	}

	return b, nil
}

// GenerateFromPassword returns the derived key of the password using the
// parameters provided.
// If the parameters provided are less than the minimum acceptable values,
// an error will be returned.
func GenerateKeyFromPassword(password []byte, salt []byte, params Params) ([]byte, []byte, error) {
	var err error
	if salt == nil {
		salt, err = GenerateRandomBytes(params.SaltLen)
		if err != nil {
			return nil, salt, err
		}
	}

	// scrypt.Key returns the raw scrypt derived key.
	dk, err := scrypt.Key(password, salt, params.N, params.R, params.P, params.DKLen)
	if err != nil {
		return nil, salt, err
	}

	return dk, salt, nil
}

func EncryptFile(srcFile, destFile string, key *[32]byte) error {
	var err error
	var bs []byte
	if bs, err = ioutil.ReadFile(srcFile); err == nil {
		if bs, err = Encrypt(bs, key); err == nil {
			dir := filepath.Dir(destFile);
			if(!FileExists(dir)){
				MkdirAll(dir);
			}
			err = ioutil.WriteFile(destFile, bs, 0644)
			return err
		}

	}
	return err
}

func DecryptFile(srcFile, destFile string, key *[32]byte) error {
	var err error
	var bs []byte
	if bs, err = ioutil.ReadFile(srcFile); err == nil {
		if bs, err = Decrypt(bs, key); err == nil {
			dir := filepath.Dir(destFile);
			if(!FileExists(dir)){
				MkdirAll(dir);
			}
			err = ioutil.WriteFile(destFile, bs, 0644)
			return err
		}

	}
	return err
}

func EncryptText(text string,  key *[32]byte) []byte {
	if bs, err := Encrypt([]byte(text), key); err == nil {
		return bs
	}
	return nil
}

func DecryptText(encrypted []byte, key *[32]byte) []byte {
	if bs, err := Decrypt(encrypted, key); err == nil {
		return bs
	}
	return nil
}

func EncryptUsingMasterKey(data []byte) ([]byte, error){
	key, err := GetClientMasterEncKey();
	if(err != nil){
		Debug("Cannot get master key")
		return nil,err
	};
	if  bs, err := Encrypt(data, &key); err == nil {
		return bs, nil;
	}else{
		return nil, err;
	}
}
func DecryptUsingMasterKey(data []byte, encKey []byte) ([]byte, error){
	var key [32]byte;
	var err error;
	if(encKey == nil) {
		key, err = GetClientMasterEncKey();
		if (err != nil) {
			Debug("Cannot get master key")
			return nil, err
		};
	}else{
		copy(key[:], encKey)
	}
	if  bs, err := Decrypt(data, &key); err == nil {
		return bs, nil;
	}else{
		return nil, err;
	}
}
