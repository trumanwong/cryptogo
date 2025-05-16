package cryptogo

import (
	"bytes"
	"fmt"
)

// UUEncode 对输入字节数组进行 uuencode 编码（不含完整的文件头，仅生成单行编码）
func UUEncode(data []byte) string {
	var buf bytes.Buffer
	// 在前面加上长度前缀，标准 uuencode 每行首字符为原始字节数加32
	buf.WriteByte(encodeUUChar(byte(len(data))))

	for i := 0; i < len(data); i += 3 {
		remain := len(data) - i
		var b [3]byte
		copy(b[:], data[i:min(i+3, len(data))])
		// 每3字节分成4组6位
		c1 := (b[0] >> 2) & 0x3F
		c2 := ((b[0] << 4) | (b[1] >> 4)) & 0x3F
		c3 := ((b[1] << 2) | (b[2] >> 6)) & 0x3F
		c4 := b[2] & 0x3F
		// 每组加32后转换成可打印字符（空格到'_'），空格用反引号代替
		buf.WriteByte(encodeUUChar(c1))
		buf.WriteByte(encodeUUChar(c2))
		if remain > 1 {
			buf.WriteByte(encodeUUChar(c3))
		} else {
			buf.WriteByte(encodeUUChar(0))
		}
		if remain > 2 {
			buf.WriteByte(encodeUUChar(c4))
		} else {
			buf.WriteByte(encodeUUChar(0))
		}
	}
	return buf.String()
}

// UUDecode 将 uuencode 字符串解码为原始字节
func UUDecode(s string) ([]byte, error) {
	var result []byte
	runes := []rune(s)
	// 第一个字符表示该行的原始数据长度
	if len(runes) < 1 {
		return nil, fmt.Errorf("empty string")
	}
	// 可选择验证首字节与剩余数据长度
	// 删除首部长度字符再处理：
	data := runes[1:]
	if len(data)%4 != 0 {
		return nil, fmt.Errorf("invalid uuencoded string length")
	}
	for i := 0; i < len(data); i += 4 {
		c1 := decodeUUChar(byte(data[i]))
		c2 := decodeUUChar(byte(data[i+1]))
		c3 := decodeUUChar(byte(data[i+2]))
		c4 := decodeUUChar(byte(data[i+3]))

		b1 := (c1 << 2) | (c2 >> 4)
		b2 := ((c2 & 0x0F) << 4) | (c3 >> 2)
		b3 := ((c3 & 0x03) << 6) | c4

		result = append(result, b1)
		if data[i+2] != '`' && data[i+2] != 0 {
			result = append(result, b2)
		}
		if data[i+3] != '`' && data[i+3] != 0 {
			result = append(result, b3)
		}
	}
	return result, nil
}

// encodeUUChar 将 6 位数据加 32 后转换为可打印字符，空格用反引号替换
func encodeUUChar(b byte) byte {
	c := b + 32
	if c == 32 {
		return byte('`')
	}
	return c
}

// decodeUUChar 将 uuencode 字符还原为 6 位数据
func decodeUUChar(c byte) byte {
	if c == '`' {
		return 0
	}
	return c - 32
}
