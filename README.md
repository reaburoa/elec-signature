# Go语言实现加密签名算法

## 签名算法
#### 目的在于在应用中更为简便的使用各类Hash、Rsa算法，生成诸如签名类数据。
### 目前支持的Hash算法主要包含：
- MD5
- SHA-1
- SHA-256
- SHA-512
- HMAC-SHA1
- HMAC-SHA256
- HMAC-SHA512
- RSA-SHA1
- RSA-SHA256

### 安装
```
go get -u github.com/reaburoa/elec-signature
```

### 使用
在使用过程中只需要引入Signature库即可轻松使用各种Hash算法生成类似签名等数据，如

```Go
package main

import (
    "fmt"
    "github.com/reaburoa/elec-signature/signature"
)

func main() {
    s := signature.Md5("testString")
    fmt.Println(s)

    sh := signature.Sha256("asdasd", "Key")
    fmt.Println(sh)

    // 将字符串私钥转化为标准格式私钥数据
    pri := signature.FastFormatPrivateKey("MIIEpQ")
    // 使用私钥生成签名，支持rsa-sha1/rsa-sha256
    sign, _ := signature.SignSha1WithRsa("string", pri)
    fmt.Println(sign)

    pub := signature.FastFormatPublicKey("MIIBITAN")
    verify := signature.VerifySignSha1WithRsa("QRYCNY282", pub)
    fmt.Println(verify)
}
```

## 加密算法
#### 目的在于在应用中更为简便的使用各类加解密算法，生成加密数据。
### 目前支持的Hash算法主要包含：
- AES

### 使用
在使用过程中只需要引入Encryption库即可轻松使用各种加密算法生成加密数据，如
```Go
package main

import (
    "fmt"
    "github.com/reaburoa/elec-signature/encryption"
)

func main() {
    e, er := encryption.AESEncrypt(
        []byte("test-foo"), // 待加密数据
        []byte("123456789012345612345678"), // 加密key
        []byte("0102030405060708"), // 加密向量iv，必须16|24|32位
        "cfb", // 加密模式，支持：cbc、cfb
    )
    fmt.Println(e, er)

    d, er := encryption.AESDecrypt(
        e, // 秘文
        "cfb", // 解密模式
        []byte("123456789012345612345678"), // 解密key
        []byte("0102030405060708"), // 解密向量iv，必须16|24|32位
    )
    fmt.Println(string(d), er)
}
```
