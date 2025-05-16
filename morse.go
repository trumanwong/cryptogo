package cryptogo

import (
	"errors"
	"fmt"
	"strings"
)

var morseLetter = map[string]string{
	"a":  ".-",
	"b":  "-...",
	"c":  "-.-.",
	"d":  "-..",
	"e":  ".",
	"f":  "..-.",
	"g":  "--.",
	"h":  "....",
	"i":  "..",
	"j":  ".---",
	"k":  "-.-",
	"l":  ".-..",
	"m":  "--",
	"n":  "-.",
	"o":  "---",
	"p":  ".--.",
	"q":  "--.-",
	"r":  ".-.",
	"s":  "...",
	"t":  "-",
	"u":  "..-",
	"v":  "...-",
	"w":  ".--",
	"x":  "-..-",
	"y":  "-.--",
	"z":  "--..",
	"ä":  ".-.-",
	"å":  ".-.-",
	"ç":  "-.-..",
	"ĉ":  "-.-..",
	"ö":  "-.-..",
	"ø":  "---.",
	"ð":  "..--.",
	"ü":  "..--",
	"ŭ":  "..--",
	"ch": "----",
	"0":  "-----",
	"1":  ".----",
	"2":  "..---",
	"3":  "...--",
	"4":  "....-",
	"5":  ".....",
	"6":  "-....",
	"7":  "--...",
	"8":  "---..",
	"9":  "----.",
	".":  ".-.-.-",
	",":  "--..--",
	"`":  ".----.",
	"?":  "..--..",
	"!":  "..--.",
	":":  "---...",
	";":  "-.-.-",
	"\"": ".-..-.",
	"'":  ".----.",
	"=":  "-...-",
	"(":  "-.--.",
	")":  "-.--.-",
	"$":  "...-..-",
	"&":  ".-...",
	"@":  ".--.-.",
	"+":  ".-.-.",
	"-":  "-....-",
	"/":  "-..-.",
}

func MorseEncode(input []byte, separator string) (dst string, err error) {
	s := ""
	if len(input) > 0 {
		s = strings.ToLower(string(input))
	}
	if strings.Contains(s, " ") {
		return dst, errors.New("can't contain spaces")
	}
	for _, letter := range s {
		let := string(letter)
		if morseLetter[let] != "" {
			dst += morseLetter[let] + separator
		}
	}
	dst = strings.Trim(dst, separator)
	return
}

func MorseDecode(src []byte, separator string) (dst string, err error) {
	s := ""
	if len(src) > 0 {
		s = string(src)
	}
	for _, part := range strings.Split(s, separator) {
		found := false
		for key, letter := range morseLetter {
			if letter == part {
				dst += key
				found = true
				break
			}
		}
		if !found {
			return dst, fmt.Errorf("unknown character " + part)
		}
	}
	return
}
