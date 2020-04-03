package signature

import (
    "crypto/hmac"
    "crypto/sha1"
    "crypto/sha256"
    "crypto/sha512"
    "encoding/hex"
    "hash"
    "strings"
)

func Hmac(str, key, sha string) string {
    var hmacHash hash.Hash
    switch strings.ToUpper(sha) {
    case "SHA-1":
        hmacHash = hmac.New(sha1.New, []byte(key))
    case "SHA-256":
        hmacHash = hmac.New(sha256.New, []byte(key))
    case "SHA-512":
        hmacHash = hmac.New(sha512.New, []byte(key))
    }
    hmacHash.Write([]byte(str))
    hashString := hmacHash.Sum(nil)
    
    return hex.EncodeToString(hashString)
}