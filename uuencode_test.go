package cryptogo

import "testing"

func TestUUEncode(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Hello World", "+2&5L;&\\@5V]R;&0`"},
		{"TrumanWong", "*5')U;6%N5V]N9P``"},
	}

	for _, test := range tests {
		result := UUEncode([]byte(test.input))
		if result != test.expected {
			t.Errorf("UUEncode(%s) = %s; expected %s", test.input, result, test.expected)
		}
	}
}

func TestUUDecode(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"+2&5L;&\\@5V]R;&0`", "Hello World"},
		{"*5')U;6%N5V]N9P``", "TrumanWong"},
	}

	for _, test := range tests {
		result, err := UUDecode(test.input)
		if err != nil {
			t.Errorf("UUDecode(%s) returned error: %v", test.input, err)
			continue
		}
		if string(result) != test.expected {
			t.Errorf("UUDecode(%s) = %s; expected %s", test.input, string(result), test.expected)
		}
	}
}
