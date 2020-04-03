# Go语言实现Hash算法
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

```
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
