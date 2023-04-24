package mode

// block cipher mode of operation
type blockMode string

const (
	CBC blockMode = "cbc"
	ECB blockMode = "ecb"
	CFB blockMode = "cfb"
	OFB blockMode = "ofb"
	CTR blockMode = "ctr"
)
