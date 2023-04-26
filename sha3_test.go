package cryptogo

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func ExampleSHA3224() {
	fmt.Println(SHA3224("TrumanWong"))
	// Output: a2bf53fa37f1e9bba362f9578ed112b7f6393c90647a7f14795c17fe
}

func TestSHA3224(t *testing.T) {
	assert.Equal(t, "602bdc204140db016bee5374895e5568ce422fabe17e064061d80097", SHA3224("123"))
}

func ExampleSHA3256() {
	fmt.Println(SHA3256("TrumanWong"))
	// Output: 8c8d0e5a5c5b5e5e5f5f606061616162626263636464656566666767
}

func TestSHA3256(t *testing.T) {
	assert.Equal(t, "a03ab19b866fc585b5cb1812a2f63ca861e7e7643ee5d43fd7106b623725fd67", SHA3256("123"))
}

func ExampleSHA3384() {
	fmt.Println(SHA3384("TrumanWong"))
	// Output: 397dd7085c0e5bce21bbd3da653289b579a145ecfde207f1e12f39cf2c843d5137f25492c78215afe166463b5a9e3e22
}

func TestSHA3384(t *testing.T) {
	assert.Equal(t, "9bd942d1678a25d029b114306f5e1dae49fe8abeeacd03cfab0f156aa2e363c988b1c12803d4a8c9ba38fdc873e5f007", SHA3384("123"))
}

func ExampleSHA3512() {
	fmt.Println(SHA3512("TrumanWong"))
	// Output: de917c20f3dbdc0299acbb61b2e0a0f62386af0a2458eb17c61469ab389773ae63a0f88e0596e2801246d2697c1212152c9e9f5839d93e03ad4b18b6a1353767
}

func TestSHA3512(t *testing.T) {
	assert.Equal(t, "48c8947f69c054a5caa934674ce8881d02bb18fb59d5a63eeaddff735b0e9801e87294783281ae49fc8287a0fd86779b27d7972d3e84f0fa0d826d7cb67dfefc", SHA3512("123"))
}

func ExampleHmacSHA3224() {
	fmt.Println(HmacSHA3224("", "TrumanWong"))
	// Output: 7ae1b1fdceebaaa89836a08909cdc310eaf25a5e7a8cf24bd0db962f
}

func TestHmacSHA3224(t *testing.T) {
	assert.Equal(t, "3e5a0b431ddf639b016549395afc3a75bb5fa75a34fa7ad370bb855f", HmacSHA3224("", "123"))
}

func ExampleHmacSHA3256() {
	fmt.Println(HmacSHA3256("", "TrumanWong"))
	// Output: fcdca5772280608a449743000c671cb34a68dcd25817ea90dc01cd9b32d26d17
}

func TestHmacSHA3256(t *testing.T) {
	assert.Equal(t, "93da3016db13103d24f19366b455377648ac68a9164e6ace71263895a7e7d3ed", HmacSHA3256("", "123"))
}

func ExampleHmacSHA3384() {
	fmt.Println(HmacSHA3384("", "TrumanWong"))
	// Output: 768313de1e3b6e600ad1ec89fc937222d3b074a6a3ce936c1354ab6bb2f4f60a475cb33cbdae65c68a8ddc1cf1b9f46a
}

func TestHmacSHA3384(t *testing.T) {
	assert.Equal(t, "4511a01d687082adfa8bc07a920759b558d8ec6b6a2ecf6437ecbcb322df4854c880249dde33aaa72df9bb7febc50e7c", HmacSHA3384("", "123"))
}

func ExampleHmacSHA3512() {
	fmt.Println(HmacSHA3512("", "TrumanWong"))
	// Output: c72a7f76f69088c775aa602791ec6488cf9c9e062bded80e168b1320394f2a0fa406d8c07f5303c2055879b69a3e4cbfa50f3b3b1fa2b85c10b24c2e4daa402e
}

func TestHmacSHA3512(t *testing.T) {
	assert.Equal(t, "8f00ba8724f31815699ca3bc1973422867edf8ca808d4b2dc715b0647d8832c306d7d1ac2e6bba580b5092c29d708333892f85d876956b821a3c400631567b50", HmacSHA3512("", "123"))
}
