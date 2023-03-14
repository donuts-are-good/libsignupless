package libsignupless

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"golang.org/x/crypto/sha3"
)

// session represents an auth session with an ID and a token
type session struct {
	ID    string `json:"id,omitempty"`
	Token string `json:"token,omitempty"`
}

// sessions is a map of authentication tokens to user IDs
var sessions = make(map[string]string)

// globalSalt is a salt for making the tokens
var globalSalt string

// init initializes the package's globalSalt using a randomly generated salt and a timestamp
func init() {
	salt, err := generateSalt(16)
	if err != nil {
		panic(fmt.Errorf("failed to generate salt: %w", err))
	}
	globalSalt = fmt.Sprintf("%x", time.Now().UnixNano()) + hex.EncodeToString(salt)
	generateToken(globalSalt, time.Now().UnixNano())
}

// generateToken generates a new authentication token using a given salt and timestamp
func generateToken(salt string, timestamp int64) string {
	thisTime := fmt.Sprintf("%x", timestamp)
	data := []byte(salt + thisTime)
	hash := sha3.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// generateSalt generates a random salt with the given length
func generateSalt(length int) ([]byte, error) {
	salt := make([]byte, length)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}

// AddSession generates a new authentication token and associates it with a user ID
// Returns the new session as a JSON string
func AddSession(id string) (string, error) {
	token := generateToken(globalSalt, time.Now().UnixNano())
	sessions[token] = id
	response := session{ID: id, Token: token}
	data, err := json.Marshal(response)
	if err != nil {
		return "", fmt.Errorf("failed to encode response: %w", err)
	}
	return string(data), nil
}

// CheckSession checks whether an authentication token is valid and returns a new one
// Returns the new session as a JSON string
func CheckSession(token string) (string, error) {
	if !validateTokenFormat(token) {
		return "", fmt.Errorf("invalid token format: %s", token)
	}
	id, exists := sessions[token]
	if !exists {
		return "", fmt.Errorf("token not found: %s", token)
	}
	newToken := generateToken(globalSalt, time.Now().UnixNano())
	sessions[newToken] = id
	response := session{ID: id, Token: newToken}
	data, err := json.Marshal(response)
	if err != nil {
		return "", fmt.Errorf("failed to encode response: %w", err)
	}
	return string(data), nil
}

// validateTokenFormat checks whether an authentication token has the correct format
func validateTokenFormat(token string) bool {
	pattern := "^[a-f0-9]{64}$"
	matched, err := regexp.MatchString(pattern, token)
	if err != nil {
		return false
	}
	return matched
}
