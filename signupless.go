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

type session struct {
	ID    string `json:"id,omitempty"`
	Token string `json:"token,omitempty"`
}

var sessions = make(map[string]string)
var globalSalt string

func init() {
	salt, err := generateSalt(16)
	if err != nil {
		panic(fmt.Errorf("failed to generate salt: %w", err))
	}
	globalSalt = fmt.Sprintf("%x", time.Now().UnixNano()) + hex.EncodeToString(salt)
	generateToken(globalSalt, time.Now().UnixNano())
}

func generateToken(salt string, timestamp int64) string {
	thisTime := fmt.Sprintf("%x", timestamp)
	data := []byte(salt + thisTime)
	hash := sha3.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func generateSalt(length int) ([]byte, error) {
	salt := make([]byte, length)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}

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

func validateTokenFormat(token string) bool {
	pattern := "^[a-f0-9]{64}$"
	matched, err := regexp.MatchString(pattern, token)
	if err != nil {
		return false
	}
	return matched
}
