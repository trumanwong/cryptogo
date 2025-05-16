package cryptogo

// VigenereEncrypt 对明文使用维吉尼亚密码加密，只加密字母，其他字符保持不变。
// 当遇到字母时，用密钥中字母（循环使用）的字母偏移量进行加密。
// 密钥中字母的偏移量按 A 或 a 为 0，B 或 b 为 1，以此类推。
func VigenereEncrypt(plaintext, key string) string {
	if len(key) == 0 {
		return plaintext
	}
	keyRunes := []rune(key)
	result := []rune{}
	ki := 0
	for _, r := range plaintext {
		if isAlpha(r) {
			base := 'A'
			if r >= 'a' && r <= 'z' {
				base = 'a'
			}
			// 获取当前密钥字母的偏移量。若密钥字母为大写或小写均可
			var shift int
			kr := keyRunes[ki%len(keyRunes)]
			if kr >= 'A' && kr <= 'Z' {
				shift = int(kr - 'A')
			} else if kr >= 'a' && kr <= 'z' {
				shift = int(kr - 'a')
			}
			// 加密当前字母
			enc := base + (r-base+rune(shift))%26
			result = append(result, enc)
			ki++
		} else {
			result = append(result, r)
		}
	}
	return string(result)
}

// VigenereDecrypt 对密文使用维吉尼亚密码解密，只解密字母，其他字符保持不变
func VigenereDecrypt(ciphertext, key string) string {
	if len(key) == 0 {
		return ciphertext
	}
	keyRunes := []rune(key)
	result := []rune{}
	ki := 0
	for _, r := range ciphertext {
		if isAlpha(r) {
			base := 'A'
			if r >= 'a' && r <= 'z' {
				base = 'a'
			}
			var shift int
			kr := keyRunes[ki%len(keyRunes)]
			if kr >= 'A' && kr <= 'Z' {
				shift = int(kr - 'A')
			} else if kr >= 'a' && kr <= 'z' {
				shift = int(kr - 'a')
			}
			dec := base + (r-base-rune(shift)+26)%26
			result = append(result, dec)
			ki++
		} else {
			result = append(result, r)
		}
	}
	return string(result)
}

// isAlpha 判断字符是否为英文字母
func isAlpha(r rune) bool {
	return (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')
}
