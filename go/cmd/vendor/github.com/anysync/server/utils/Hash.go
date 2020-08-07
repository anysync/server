// Copyright (c) 2020, Yanbin (Henry) Zheng <ybzheng@gmail.com>
// All rights reserved.
//
// Use of this source code is governed by a AGPLv3 license that can be
// found in the LICENSE file.
package utils

import (
	"hash"
	"crypto/hmac"
	"crypto/sha256"
	"golang.org/x/crypto/sha3"
	//"crypto/md5"
)
const(
	HASH_BYTE_COUNT = 28
	NULL_HASH                   = "00000000000000000000000000000000000000000000000000000000"
	SHARED_HASH                 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	SHARED_FILE_NAME_HASH                 = "fffffffffffffffffffffffffffffffffffffffffffffffffffffff0"
	ZERO_HASH                   = "f8cdb04495ded47615258f9dc6a3f4707fd2405434fefc3cbf4ef4e6"
)

//SHA256-HMAC
func NewHmac(key[]byte)hash.Hash{
	return hmac.New(sha256.New, key);
}

func NewHash() hash.Hash {
	return sha3.New224();
}

func SumSuffix(h hash.Hash, suffix string)[]byte{
	h.Write([]byte(suffix))
	return h.Sum(nil);
}

func NewHashWithHeader(header[]byte) hash.Hash {
	h := sha3.New224();
	h.Write(header);
	return h;
}

func SumWithTail(h hash.Hash, tail []byte)[]byte{
	h.Write(tail);
	if(GetHashSuffix() == ""){
		Critical("Empty HASH Suffix")
	}
	return h.Sum(nil);
}

func NewHmacSha224(key[]byte)hash.Hash{
	return hmac.New(sha256.New224, key);
}
