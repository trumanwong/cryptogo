package cryptogo

import "unicode"

// CaesarEncrypt 对明文使用 Caesar 密码进行加密，shift 为偏移量
func CaesarEncrypt(plaintext string, shift int) string {
	shift = shift % 26
	if shift < 0 {
		shift += 26
	}
	runes := []rune(plaintext)
	for i, r := range runes {
		if unicode.IsUpper(r) {
			runes[i] = 'A' + (r-'A'+rune(shift))%26
		} else if unicode.IsLower(r) {
			runes[i] = 'a' + (r-'a'+rune(shift))%26
		}
		// 非字母保持不变
	}
	return string(runes)
}

// CaesarDecrypt 对密文使用 Caesar 密码进行解密，shift 为加密时的偏移量
func CaesarDecrypt(ciphertext string, shift int) string {
	// 解密即反向偏移
	return CaesarEncrypt(ciphertext, -shift)
}
