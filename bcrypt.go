package cryptogo

import "golang.org/x/crypto/bcrypt"

// PasswordHash returns the bcrypt hash of the password at the given cost.
// PasswordHash does not accept passwords longer than 72 bytes
func PasswordHash(clearText []byte, cost int) ([]byte, error) {
	fromPassword, err := bcrypt.GenerateFromPassword(clearText, cost)
	if err != nil {
		return nil, err
	}
	return fromPassword, nil
}

// PasswordVerify compares a bcrypt hashed password with its possible
// plaintext equivalent. Returns nil on success, or an error on failure.
func PasswordVerify(clearText, hashedPassword []byte) bool {
	err := bcrypt.CompareHashAndPassword(hashedPassword, clearText)
	return err == nil
}
