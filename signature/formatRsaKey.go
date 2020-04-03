package signature

func FormatPrivateKey(privateKey string) string {
    tempKey := []byte(privateKey)
    length := len(tempKey)
    formatPriKey := "-----BEGIN RSA PRIVATE KEY-----\n"
    tail := make([]byte, length)
    for i := 0; i < length; i++ {
        if (i+1)%64 == 0 {
            head := tempKey[i-63 : i+1]
            tail = tempKey[i+1:]
            formatPriKey += string(head) + "\n"
        }
    }
    formatPriKey += string(tail) + "\n"
    formatPriKey += "-----END RSA PRIVATE KEY-----\n"
    return formatPriKey
}

func FastFormatPrivateKey(privateKey string) []byte {
    tempKey := []byte(privateKey)
    length := len(tempKey)
    page := length / 64
    formatPriKey := "-----BEGIN RSA PRIVATE KEY-----\n"
    for i := 0; i < page; i++ {
        formatPriKey += string(tempKey[i*64:(i+1)*64]) + "\n"
    }
    formatPriKey += string(tempKey[page*64:]) + "\n"
    formatPriKey += "-----END RSA PRIVATE KEY-----\n"
    return []byte(formatPriKey)
}

func FastFormatPublicKey(publicKey string) []byte {
    tempKey := []byte(publicKey)
    length := len(tempKey)
    page := length / 64
    formatPubKey := "-----BEGIN PUBLIC KEY-----\n"
    for i := 0; i < page; i++ {
        formatPubKey += string(tempKey[i*64:(i+1)*64]) + "\n"
    }
    formatPubKey += string(tempKey[page*64:]) + "\n"
    formatPubKey += "-----END PUBLIC KEY-----\n"
    return []byte(formatPubKey)
}
