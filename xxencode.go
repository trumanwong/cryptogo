package cryptogo

import (
	"fmt"
)

const xxTable = "+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// XXEncode 对输入字节数组进行 xxencode 编码（单行编码，不含完整文件头）。
// 规则：
//  1. 行首字符为原始数据长度对应的字符，计算方式为：xxTable[len(data)]
//     （要求 len(data) 不大于 63）。
//  2. 每 3 字节分成 4 个 6 位数据，分别用 xxTable 映射成字符。
//     对于不足 3 字节的数据块，按 0 填充。
func XXEncode(data []byte) string {
	// 计算前缀：数据字节数对应的字符
	if len(data) > 63 {
		// 本实现仅处理单行且长度 <= 63 的情况
		panic("data length exceeds 63")
	}

	out := make([]byte, 0, 1+((len(data)+2)/3)*4)
	// 前缀字符
	out = append(out, xxTable[len(data)])

	// 每 3 字节处理一次
	for i := 0; i < len(data); i += 3 {
		remain := len(data) - i
		var b [3]byte
		for j := 0; j < 3; j++ {
			if j < remain {
				b[j] = data[i+j]
			} else {
				b[j] = 0
			}
		}
		// 将3字节分成4个6位数字
		c1 := b[0] >> 2
		c2 := ((b[0] & 0x03) << 4) | (b[1] >> 4)
		c3 := ((b[1] & 0x0F) << 2) | (b[2] >> 6)
		c4 := b[2] & 0x3F

		out = append(out, xxTable[c1])
		out = append(out, xxTable[c2])
		// 当不足 2 字节时仍输出映射（填充的 0 会映射到 xxTable[0]）
		out = append(out, xxTable[c3])
		out = append(out, xxTable[c4])
	}
	return string(out)
}

// XXDecode 将 xxencode 编码的字符串解码为原始字节数据
func XXDecode(s string) ([]byte, error) {
	if len(s) < 1 {
		return nil, fmt.Errorf("empty string")
	}
	// 通过前缀得到原始数据长度
	prefix := s[0]
	// 在 xxTable 中查找 prefix 对应的索引
	origLen := -1
	for i := 0; i < len(xxTable); i++ {
		if xxTable[i] == prefix {
			origLen = i
			break
		}
	}
	if origLen < 0 {
		return nil, fmt.Errorf("invalid prefix character")
	}

	data := s[1:]
	if len(data)%4 != 0 {
		return nil, fmt.Errorf("invalid xxencoded string length")
	}

	// 解码每4字符恢复3个字节
	out := make([]byte, 0, (len(data)/4)*3)
	for i := 0; i < len(data); i += 4 {
		c1, ok := decodeXXChar(data[i])
		if !ok {
			return nil, fmt.Errorf("invalid character: %c", data[i])
		}
		c2, ok := decodeXXChar(data[i+1])
		if !ok {
			return nil, fmt.Errorf("invalid character: %c", data[i+1])
		}
		c3, ok := decodeXXChar(data[i+2])
		if !ok {
			return nil, fmt.Errorf("invalid character: %c", data[i+2])
		}
		c4, ok := decodeXXChar(data[i+3])
		if !ok {
			return nil, fmt.Errorf("invalid character: %c", data[i+3])
		}

		b1 := (c1 << 2) | (c2 >> 4)
		b2 := ((c2 & 0x0F) << 4) | (c3 >> 2)
		b3 := ((c3 & 0x03) << 6) | c4

		out = append(out, b1, b2, b3)
	}

	// 按前缀还原原始数据长度
	if origLen > len(out) {
		return nil, fmt.Errorf("invalid original length")
	}
	return out[:origLen], nil
}

// decodeXXChar 将 xxencode 字符转换为 6 位数值
func decodeXXChar(c byte) (byte, bool) {
	// 在 xxTable 中查找字符 c 的索引
	for i := 0; i < len(xxTable); i++ {
		if xxTable[i] == c {
			return byte(i), true
		}
	}
	return 0, false
}
