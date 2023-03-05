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
