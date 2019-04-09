package signature

import (
    "encoding/pem"
    "crypto/x509"
    "crypto/rsa"
    "crypto"
    "encoding/base64"
    "crypto/rand"
    "crypto/sha1"
    "crypto/sha256"
    "errors"
)

func getPublicKey(publicKey []byte) (*rsa.PublicKey, error) {
    block, _ := pem.Decode(publicKey)
    pub, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
        return nil, err
    }

    return pub.(*rsa.PublicKey), nil
}

func getPrivateKey(privateKey []byte) (*rsa.PrivateKey, error) {
    block, _ := pem.Decode(privateKey)
    if block == nil {
        return nil, errors.New("RsaSign PrivateKey Error")
    }
    p, err := x509.ParsePKCS8PrivateKey(block.Bytes)
    if err == nil {
        return p.(*rsa.PrivateKey), nil
    }

    pri, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
        return nil, err
    }
    return pri, nil
}

func SignSha1WithRsa(data string, privateKey []byte) (string, error) {
    pri, err := getPrivateKey(privateKey)
    if err != nil {
        panic(err.Error())
    }

    sha1Hash := sha1.New()
    s_data := []byte(data)
    sha1Hash.Write(s_data)
    hashed := sha1Hash.Sum(nil)

    signByte, err := rsa.SignPKCS1v15(rand.Reader, pri, crypto.SHA1, hashed)
    sign := base64.StdEncoding.EncodeToString(signByte)
    return sign, err
}

func VerifySignSha1WithRsa(data string, signData string, publicKey []byte) error {
    pub, err := getPublicKey(publicKey)
    if err != nil {
        return err
    }

    sign, err := base64.StdEncoding.DecodeString(signData)
    if err != nil {
        return err
    }
    hash := sha1.New()
    hash.Write([]byte(data))
    return rsa.VerifyPKCS1v15(pub, crypto.SHA1, hash.Sum(nil), sign)
}

func SignSha256WithRsa(data string, privateKey []byte) (string, error) {
    pri, err := getPrivateKey(privateKey)
    if err != nil {
        panic(err.Error())
    }

    sha256Hash := sha256.New()
    s_data := []byte(data)
    sha256Hash.Write(s_data)
    hashed := sha256Hash.Sum(nil)

    signByte, err := rsa.SignPKCS1v15(rand.Reader, pri, crypto.SHA256, hashed)
    sign := base64.StdEncoding.EncodeToString(signByte)
    return sign, err
}

func VerifySignSha256WithRsa(data string, signData string, publicKey []byte) error {
    pub, err := getPublicKey(publicKey)
    if err != nil {
        return err
    }

    sign, err := base64.StdEncoding.DecodeString(signData)
    if err != nil {
        return err
    }
    hash := sha256.New()
    hash.Write([]byte(data))

    return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash.Sum(nil), sign)
}
