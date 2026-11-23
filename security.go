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

// passwordMatches reports whether password is the one hash was made from, and
// costs one full bcrypt comparison whatever hash is. It is the comparison of
// the two password logins, POST <prefix>/login (loginPassword) and POST
// <admin>/login.
//
// verifyPassword alone answers at once for a hash bcrypt cannot parse — "" for
// an account that never had a password, a marker a migration left in the
// column — because bcrypt refuses it before any key derivation, while a real
// hash costs a whole comparison. A login answering on that difference says
// which kind of account an address holds, so an unparseable hash is refused
// after a comparison against the stand-in hash instead (spendPasswordComparison).
// A real hash is compared at its own cost: the deployment's, unless it was
// written before Config.BcryptCost last changed.
func (s *Service) passwordMatches(password, hash string) bool {
	if _, err := bcrypt.Cost([]byte(hash)); err != nil {
		s.spendPasswordComparison(password)
		return false
	}
	return s.compareHash([]byte(hash), []byte(password)) == nil
}

// spendPasswordComparison runs the comparison a login makes when there is no
// hash to compare against — an address no account holds, or an account whose
// stored value is not a bcrypt hash — so that refusing it costs what refusing a
// wrong password costs. The result is discarded: only the work matters.
func (s *Service) spendPasswordComparison(password string) {
	_ = s.compareHash(s.dummyPasswordHash(), []byte(password))
}

// dummyPassword is what the stand-in hash is made from. Its value does not
// matter: nothing is ever stored under it and the comparison's result is never
// read.
const dummyPassword = "awesome-go-auth: no account holds this password"

// dummyPasswordHash is the stand-in hash spendPasswordComparison compares
// against, written at the cost every new hash is written at — Config.BcryptCost,
// bcrypt.DefaultCost when it is unset — so that the comparison costs what a
// comparison against a real hash costs.
//
// It is computed once per Service, on first use rather than in NewService:
// generating it costs as much as a comparison, which a cold start that never
// refuses a login should not pay (a Lambda consumer allows costs up to 15).
// The first refusal after a start therefore pays twice, once.
func (s *Service) dummyPasswordHash() []byte {
	s.dummyHashOnce.Do(func() {
		hash, err := hashPassword(dummyPassword, s.cfg.BcryptCost)
		if err != nil {
			// Unreachable through a validated Config, whose cost bcrypt
			// accepts. Were it reached, the comparison against a nil hash
			// fails at once: the refusals stay refusals and only lose their
			// cover, which the log says.
			s.logf("auth: the stand-in password hash could not be computed, so refused logins are not cost-equalised: %v", err)
			return
		}
		s.dummyHash = []byte(hash)
	})
	return s.dummyHash
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
