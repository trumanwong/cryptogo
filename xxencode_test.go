package cryptogo

import "testing"

func TestXXEncode(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Hello World", "9G4JgP4wUJqxmP4E+"},
		{"TrumanWong", "8J57pPK3iJqxiNk++"},
	}

	for _, test := range tests {
		result := XXEncode([]byte(test.input))
		if result != test.expected {
			t.Errorf("XXEncode(%s) = %s; expected %s", test.input, result, test.expected)
		}
	}
}

func TestXXDecode(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"9G4JgP4wUJqxmP4E+", "Hello World"},
		{"8J57pPK3iJqxiNk++", "TrumanWong"},
	}

	for _, test := range tests {
		result, err := XXDecode(test.input)
		if err != nil {
			t.Errorf("XXDecode(%s) error: %v", test.input, err)
			continue
		}
		if string(result) != test.expected {
			t.Errorf("XXDecode(%s) = %s; expected %s", test.input, result, test.expected)
		}
	}
}
