package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

const randomIDBytes = 16

func newID(prefix string) (string, error) {
	b := make([]byte, randomIDBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: random id: %w", err)
	}
	return prefix + "_" + hex.EncodeToString(b), nil
}

// bcryptMaxPasswordBytes is the longest password hashPassword can hash:
// golang.org/x/crypto/bcrypt refuses a longer one with ErrPasswordTooLong
// rather than truncate it, as some bcrypt libraries do. It is a count of bytes,
// not of characters: 25 four-byte runes are 100 bytes.
const bcryptMaxPasswordBytes = 72

// hashPassword hashes password at the given bcrypt cost.
//
// A password longer than bcryptMaxPasswordBytes is an error, bcrypt's own,
// wrapped like any other failure. A caller that must not fail after a
// side effect it cannot take back checks the length first, as
// Service.AcceptInvitation does before it spends the invitation's token.
//
// A zero cost means "unset" and resolves to bcrypt.DefaultCost. This is the one
// place that resolution happens, so every caller may pass Config.BcryptCost
// straight through without repeating the check.
//
// GenerateFromPassword documents the same substitution for any cost below
// MinCost, so the branch below is not what makes the behaviour correct. It is
// what makes it ours: the rule that an unconfigured deployment gets DefaultCost
// and never MinCost is a password policy, and it should be stated and tested
// here rather than inherited from a dependency that is free to change it.
//
// Costs outside [bcrypt.MinCost, bcrypt.MaxCost] cannot reach here through a
// validated Config. If one does, bcrypt's own handling applies: anything below
// MinCost is raised to DefaultCost, and anything above MaxCost is an
// InvalidCostError, wrapped like any other failure. Neither case can produce a
// hash weaker than DefaultCost.
func hashPassword(password string, cost int) (string, error) {
	if cost == 0 {
		cost = bcrypt.DefaultCost
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", fmt.Errorf("auth: hash password: %w", err)
	}
	return string(h), nil
}

func verifyPassword(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func randomToken(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func randomNumericCode(length int) (string, error) {
	const digits = "0123456789"
	if length <= 0 {
		return "", errors.New("invalid code length")
	}
	out := make([]byte, length)
	for i := range out {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		if err != nil {
			return "", fmt.Errorf("auth: random code: %w", err)
		}
		out[i] = digits[n.Int64()]
	}
	return string(out), nil
}

func sign(input, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(input))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func secureEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// splitToken splits a compact JWS serialization into its header, payload and
// signature segments.
func splitToken(token string) (header, payload, sig string, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", "", errors.New("invalid token format")
	}
	return parts[0], parts[1], parts[2], nil
}
