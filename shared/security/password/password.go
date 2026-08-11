package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"golang.org/x/crypto/argon2"
)

// commonPasswords is a list of the top 20 most common passwords used for rejection.
var commonPasswords = []string{
	"password",
	"123456",
	"12345678",
	"qwerty",
	"abc123",
	"password1",
	"password123",
	"1234567",
	"123456789",
	"1234567890",
	"letmein",
	"iloveyou",
	"admin",
	"welcome",
	"monkey",
	"master",
	"dragon",
	"login",
	"princess",
	"football",
}

var (
	ErrInvalidPassword = errors.New("invalid password")
	ErrInvalidHash     = errors.New("invalid hash format")
)

// PasswordService handles password hashing and verification using Argon2id.
// The service mirrors the AuthService defaults so other services can share the implementation.
type PasswordService struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

// NewPasswordService creates a new password service with secure defaults.
func NewPasswordService() *PasswordService {
	return &PasswordService{
		memory:      64 * 1024, // 64 MB
		iterations:  3,
		parallelism: 2,
		saltLength:  16,
		keyLength:   32,
	}
}

// HashPassword hashes a password using Argon2id.
func (p *PasswordService) HashPassword(password string) (string, error) {
	if len(password) == 0 {
		return "", ErrInvalidPassword
	}

	salt, err := p.generateRandomBytes(p.saltLength)
	if err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, p.iterations, p.memory, p.parallelism, p.keyLength)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.memory, p.iterations, p.parallelism, b64Salt, b64Hash)

	return encoded, nil
}

// VerifyPassword verifies a password against a hash.
func (p *PasswordService) VerifyPassword(password, encodedHash string) (bool, error) {
	if len(password) == 0 || len(encodedHash) == 0 {
		return false, ErrInvalidPassword
	}

	memory, iterations, parallelism, salt, hash, err := p.decodeHash(encodedHash)
	if err != nil {
		return false, err
	}

	otherHash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, p.keyLength)
	return subtle.ConstantTimeCompare(hash, otherHash) == 1, nil
}

func (p *PasswordService) generateRandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (p *PasswordService) decodeHash(encodedHash string) (memory uint32, iterations uint32, parallelism uint8, salt, hash []byte, err error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return 0, 0, 0, nil, nil, ErrInvalidHash
	}

	var version int
	if _, err = fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return 0, 0, 0, nil, nil, ErrInvalidHash
	}
	if version != argon2.Version {
		return 0, 0, 0, nil, nil, ErrInvalidHash
	}

	if _, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return 0, 0, 0, nil, nil, ErrInvalidHash
	}

	if salt, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil {
		return 0, 0, 0, nil, nil, ErrInvalidHash
	}

	if hash, err = base64.RawStdEncoding.DecodeString(parts[5]); err != nil {
		return 0, 0, 0, nil, nil, ErrInvalidHash
	}

	return memory, iterations, parallelism, salt, hash, nil
}

// GenerateRandomPassword generates a cryptographically secure random password.
func GenerateRandomPassword(length int) (string, error) {
	if length < 8 {
		length = 8
	}

	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	b := make([]byte, length)

	charsetLen := big.NewInt(int64(len(charset)))
	for i := range b {
		idx, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return "", err
		}
		b[i] = charset[idx.Int64()]
	}

	return string(b), nil
}

// ValidatePasswordStrength enforces baseline password policy.
func ValidatePasswordStrength(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters long")
	}

	if len(password) > 72 {
		return errors.New("Password must not exceed 72 characters")
	}

	for _, common := range commonPasswords {
		if strings.EqualFold(password, common) {
			return errors.New("password is too common, please choose a more unique password")
		}
	}

	var (
		hasUpper   = false
		hasLower   = false
		hasNumber  = false
		hasSpecial = false
	)

	for _, char := range password {
		switch {
		case 'a' <= char && char <= 'z':
			hasLower = true
		case 'A' <= char && char <= 'Z':
			hasUpper = true
		case '0' <= char && char <= '9':
			hasNumber = true
		default:
			hasSpecial = true
		}
	}

	if !hasLower {
		return errors.New("password must contain at least one lowercase letter")
	}
	if !hasUpper {
		return errors.New("password must contain at least one uppercase letter")
	}
	if !hasNumber {
		return errors.New("password must contain at least one number")
	}
	if !hasSpecial {
		return errors.New("password must contain at least one special character")
	}

	return nil
}
