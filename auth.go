package main

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// HashPassword создает безопасный хеш пароля с использованием bcrypt
func HashPassword(password string) (string, error) {
	const cost = 12
	
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", fmt.Errorf("ошибка хеширования пароля: %v", err)
	}
	
	return string(hashedBytes), nil
}

// VerifyPassword проверяет соответствие пароля его хешу
func VerifyPassword(password, hashedPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

// IsPasswordSecure проверяет, является ли пароль достаточно безопасным
func IsPasswordSecure(password string) (bool, []string) {
	rules := DefaultPasswordRules()
	return ValidatePassword(password, rules)
}