package signature

import (
    "crypto/sha1"
    "crypto/sha256"
    "crypto/sha512"
    "encoding/hex"
)

func Sha1(data, key string) string {
    hash := sha1.New()
    hash.Write([]byte(key + data))
    hashString := hash.Sum(nil)
    return hex.EncodeToString(hashString)
}

func Sha256(data, key string) string {
    hash := sha256.New()
    hash.Write([]byte(key + data))
    hashString := hash.Sum(nil)
    return hex.EncodeToString(hashString)
}

func Sha512(data, key string) string {
    hash := sha512.New()
    hash.Write([]byte(key + data))
    hashString := hash.Sum(nil)
    return hex.EncodeToString(hashString)
}
