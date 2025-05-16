package cryptogo

import (
	"fmt"
)

const (
	first  = 0xf0
	second = 0x9f

	shift   = 55
	divisor = 64

	third = 0x8f
	forth = 0x80
)

// Base100Encode 将字节数组编码为Base100字符串
func Base100Encode(data []byte) string {
	result := make([]byte, len(data)*4)
	for i, b := range data {
		result[i*4+0] = first
		result[i*4+1] = second
		result[i*4+2] = byte((uint16(b)+shift)/divisor + third)
		result[i*4+3] = (b+shift)%divisor + forth
	}
	return string(result)
}

// Base100Decode 将Base100字符串解码为字节数组
func Base100Decode(data string) ([]byte, error) {
	if len(data)%4 != 0 {
		return nil, fmt.Errorf("invalid base100 string length, should be divisible by 4")
	}

	result := make([]byte, len(data)/4)
	for i := 0; i != len(data); i += 4 {
		if data[i+0] != first || data[i+1] != second {
			return nil, fmt.Errorf("invalid base100 string")
		}

		result[i/4] = (data[i+2]-third)*divisor +
			data[i+3] - forth - shift
	}
	return result, nil
}
