package encryption

import (
    "bytes"
    "crypto/aes"
    "crypto/cipher"
    "encoding/base64"
    "errors"
    "strings"
)

// 补码
func padding(orig []byte, blockSize int) []byte {
    padding := blockSize - len(orig)%blockSize
    paddingText := bytes.Repeat([]byte{byte(padding)}, padding)
    return append(orig, paddingText...)
}

// 反补码
func unPadding(orig []byte) []byte {
    length := len(orig)
    padding := int(orig[length-1])
    return orig[:(length - padding)]
}

// 加密
func AESEncrypt(orig, key, iv []byte, mod string) (string, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return "", errors.New("Key Length Must 16|24|32")
    }
    blockSize := block.BlockSize()
    orig = padding(orig, blockSize)
    cipherText := make([]byte, len(orig))
    switch strings.ToUpper(mod) {
    case "CBC":
        blockMode := cipher.NewCBCEncrypter(block, iv)
        blockMode.CryptBlocks(cipherText, orig)
    case "CFB":
        blockMode := cipher.NewCFBEncrypter(block, iv)
        blockMode.XORKeyStream(cipherText, orig)
    default:
        return "", errors.New("Encrypt Mode Must CBC、CFB")
    }
    return base64.StdEncoding.EncodeToString(cipherText), nil
}

// 解密
func AESDecrypt(encrypt, mod string, key, iv []byte) ([]byte, error) {
    byData, err := base64.StdEncoding.DecodeString(encrypt)
    if err != nil {
        return nil, errors.New("Data Error")
    }
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, errors.New("Key Length Must 16|24|32")
    }
    
    blockSize := block.BlockSize()
    if len(byData) < blockSize {
        return nil, errors.New("Encrypt Data Too Short")
    }
    
    if len(byData)%blockSize != 0 {
        return nil, errors.New("Encrypt Data Is Not A Multiple Of The Block Size")
    }
    
    orig := make([]byte, len(byData))
    switch strings.ToUpper(mod) {
    case "CBC":
        blockMode := cipher.NewCBCDecrypter(block, iv)
        blockMode.CryptBlocks(orig, byData)
    case "CFB":
        blockMode := cipher.NewCFBDecrypter(block, iv)
        blockMode.XORKeyStream(orig, byData)
    default:
        return nil, errors.New("Encrypt Mode Must CBC、CFB")
    }
    
    orig = unPadding(orig)
    return orig, nil
}
