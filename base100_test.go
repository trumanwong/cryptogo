package cryptogo

import "testing"

func TestBase100Encode(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Hello World", "🐿👜👣👣👦🐗👎👦👩👣👛"},
		{"TrumanWong", "👋👩👬👤👘👥👎👦👥👞"},
		{"你好, 世界", "📛💴💗📜💜💴🐣🐗📛💯💍📞💌💃"},
	}

	for _, test := range tests {
		result := Base100Encode([]byte(test.input))
		if result != test.expected {
			t.Errorf("Base100Encode(%s) = %s; expected %s", test.input, result, test.expected)
		}
	}
}

func TestBase100Decode(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"🐿👜👣👣👦🐗👎👦👩👣👛", "Hello World"},
		{"👋👩👬👤👘👥👎👦👥👞", "TrumanWong"},
		{"📛💴💗📜💜💴🐣🐗📛💯💍📞💌💃", "你好, 世界"},
	}

	for _, test := range tests {
		result, err := Base100Decode(test.input)
		if err != nil {
			t.Errorf("Base100Decode(%s) returned error: %v", test.input, err)
			continue
		}
		if string(result) != test.expected {
			t.Errorf("Base100Decode(%s) = %s; expected %s", test.input, string(result), test.expected)
		}
	}
}
