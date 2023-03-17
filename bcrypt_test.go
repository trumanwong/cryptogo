package cryptogo

import (
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
	"testing"
)

func TestPasswordHash(t *testing.T) {
	t.Run("TestPasswordHash", func(t *testing.T) {
		password, err := PasswordHash([]byte("TrumanWong"), bcrypt.DefaultCost)
		assert.Equal(t, nil, err)
		assert.Equal(t, true, PasswordVerify([]byte("TrumanWong"), password))
	})
}

func TestPasswordVerify(t *testing.T) {
	t.Run("TestPasswordVerify", func(t *testing.T) {
		assert.Equal(t, true, PasswordVerify([]byte("TrumanWong"), []byte("$2a$10$hP8hjVvY1Zsehzk05L0XMOaoiDo1NbACDOGbmORPMjT7YIMp8UOsm")))
	})
}
