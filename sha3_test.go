package cryptogo

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSHA3224(t *testing.T) {
	assert.Equal(t, "602bdc204140db016bee5374895e5568ce422fabe17e064061d80097", SHA3224("123"))
}

func TestSHA3256(t *testing.T) {
	assert.Equal(t, "a03ab19b866fc585b5cb1812a2f63ca861e7e7643ee5d43fd7106b623725fd67", SHA3256("123"))
}

func TestSHA3384(t *testing.T) {
	assert.Equal(t, "9bd942d1678a25d029b114306f5e1dae49fe8abeeacd03cfab0f156aa2e363c988b1c12803d4a8c9ba38fdc873e5f007", SHA3384("123"))
}

func TestSHA3512(t *testing.T) {
	assert.Equal(t, "48c8947f69c054a5caa934674ce8881d02bb18fb59d5a63eeaddff735b0e9801e87294783281ae49fc8287a0fd86779b27d7972d3e84f0fa0d826d7cb67dfefc", SHA3512("123"))
}

func TestHmacSHA3224(t *testing.T) {
	assert.Equal(t, "3e5a0b431ddf639b016549395afc3a75bb5fa75a34fa7ad370bb855f", HmacSHA3224("", "123"))
}

func TestHmacSHA3256(t *testing.T) {
	assert.Equal(t, "93da3016db13103d24f19366b455377648ac68a9164e6ace71263895a7e7d3ed", HmacSHA3256("", "123"))
}

func TestHmacSHA3384(t *testing.T) {
	assert.Equal(t, "4511a01d687082adfa8bc07a920759b558d8ec6b6a2ecf6437ecbcb322df4854c880249dde33aaa72df9bb7febc50e7c", HmacSHA3384("", "123"))
}

func TestHmacSHA3512(t *testing.T) {
	assert.Equal(t, "8f00ba8724f31815699ca3bc1973422867edf8ca808d4b2dc715b0647d8832c306d7d1ac2e6bba580b5092c29d708333892f85d876956b821a3c400631567b50", HmacSHA3512("", "123"))
}
