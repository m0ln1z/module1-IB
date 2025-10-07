package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
)

// PasswordRules определяет правила для генерации паролей
type PasswordRules struct {
	Length           int  // Минимальная длина пароля
	RequireUppercase bool // Требует заглавные буквы
	RequireLowercase bool // Требует строчные буквы
	RequireDigits    bool // Требует цифры
	RequireSpecial   bool // Требует специальные символы
	MinUppercase     int  // Минимальное количество заглавных букв
	MinLowercase     int  // Минимальное количество строчных букв
	MinDigits        int  // Минимальное количество цифр
	MinSpecial       int  // Минимальное количество специальных символов
}

// DefaultPasswordRules возвращает стандартные безопасные правила для паролей
func DefaultPasswordRules() PasswordRules {
	return PasswordRules{
		Length:           12, // Минимум 12 символов для безопасности
		RequireUppercase: true,
		RequireLowercase: true,
		RequireDigits:    true,
		RequireSpecial:   true,
		MinUppercase:     2, // Минимум 2 заглавные буквы
		MinLowercase:     2, // Минимум 2 строчные буквы
		MinDigits:        2, // Минимум 2 цифры
		MinSpecial:       2, // Минимум 2 специальных символа
	}
}

// Наборы символов для генерации паролей
const (
	uppercaseLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lowercaseLetters = "abcdefghijklmnopqrstuvwxyz"
	digits           = "0123456789"
	specialChars     = "!@#$%^&*()_+-=[]{}|;:,.<>?"
)

// GeneratePassword генерирует безопасный пароль согласно заданным правилам
func GeneratePassword(rules PasswordRules) (string, error) {
	if rules.Length < 4 {
		return "", fmt.Errorf("длина пароля должна быть минимум 4 символа")
	}

	// Проверим, что минимальные требования не превышают общую длину
	minRequired := rules.MinUppercase + rules.MinLowercase + rules.MinDigits + rules.MinSpecial
	if minRequired > rules.Length {
		return "", fmt.Errorf("сумма минимальных требований (%d) превышает длину пароля (%d)", minRequired, rules.Length)
	}

	var password []rune
	var remainingLength = rules.Length

	// Добавляем обязательные символы каждого типа
	if rules.RequireUppercase && rules.MinUppercase > 0 {
		chars, err := generateCharsFromSet(uppercaseLetters, rules.MinUppercase)
		if err != nil {
			return "", err
		}
		password = append(password, chars...)
		remainingLength -= rules.MinUppercase
	}

	if rules.RequireLowercase && rules.MinLowercase > 0 {
		chars, err := generateCharsFromSet(lowercaseLetters, rules.MinLowercase)
		if err != nil {
			return "", err
		}
		password = append(password, chars...)
		remainingLength -= rules.MinLowercase
	}

	if rules.RequireDigits && rules.MinDigits > 0 {
		chars, err := generateCharsFromSet(digits, rules.MinDigits)
		if err != nil {
			return "", err
		}
		password = append(password, chars...)
		remainingLength -= rules.MinDigits
	}

	if rules.RequireSpecial && rules.MinSpecial > 0 {
		chars, err := generateCharsFromSet(specialChars, rules.MinSpecial)
		if err != nil {
			return "", err
		}
		password = append(password, chars...)
		remainingLength -= rules.MinSpecial
	}

	// Заполняем оставшуюся длину случайными символами из всех доступных наборов
	if remainingLength > 0 {
		allChars := ""
		if rules.RequireUppercase {
			allChars += uppercaseLetters
		}
		if rules.RequireLowercase {
			allChars += lowercaseLetters
		}
		if rules.RequireDigits {
			allChars += digits
		}
		if rules.RequireSpecial {
			allChars += specialChars
		}

		if allChars == "" {
			return "", fmt.Errorf("не выбран ни один набор символов")
		}

		chars, err := generateCharsFromSet(allChars, remainingLength)
		if err != nil {
			return "", err
		}
		password = append(password, chars...)
	}

	// Перемешиваем пароль для рандомизации позиций символов
	if err := shuffleRunes(password); err != nil {
		return "", err
	}

	return string(password), nil
}

// generateCharsFromSet генерирует заданное количество случайных символов из набора
func generateCharsFromSet(charset string, count int) ([]rune, error) {
	chars := make([]rune, count)
	charsetRunes := []rune(charset)
	charsetLen := big.NewInt(int64(len(charsetRunes)))

	for i := 0; i < count; i++ {
		randomIndex, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return nil, fmt.Errorf("ошибка генерации случайного числа: %v", err)
		}
		chars[i] = charsetRunes[randomIndex.Int64()]
	}

	return chars, nil
}

// shuffleRunes перемешивает массив рун используя алгоритм Fisher-Yates
func shuffleRunes(runes []rune) error {
	n := len(runes)
	for i := n - 1; i > 0; i-- {
		randomIndex, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return fmt.Errorf("ошибка генерации случайного числа для перемешивания: %v", err)
		}
		j := randomIndex.Int64()
		runes[i], runes[j] = runes[j], runes[i]
	}
	return nil
}

// ValidatePassword проверяет, соответствует ли пароль заданным правилам
func ValidatePassword(password string, rules PasswordRules) (bool, []string) {
	var errors []string

	// Проверка длины
	if len(password) < rules.Length {
		errors = append(errors, fmt.Sprintf("пароль должен содержать минимум %d символов", rules.Length))
	}

	// Подсчет символов каждого типа
	var uppercaseCount, lowercaseCount, digitCount, specialCount int

	for _, char := range password {
		switch {
		case strings.ContainsRune(uppercaseLetters, char):
			uppercaseCount++
		case strings.ContainsRune(lowercaseLetters, char):
			lowercaseCount++
		case strings.ContainsRune(digits, char):
			digitCount++
		case strings.ContainsRune(specialChars, char):
			specialCount++
		}
	}

	// Проверка требований
	if rules.RequireUppercase && uppercaseCount < rules.MinUppercase {
		errors = append(errors, fmt.Sprintf("пароль должен содержать минимум %d заглавных букв", rules.MinUppercase))
	}

	if rules.RequireLowercase && lowercaseCount < rules.MinLowercase {
		errors = append(errors, fmt.Sprintf("пароль должен содержать минимум %d строчных букв", rules.MinLowercase))
	}

	if rules.RequireDigits && digitCount < rules.MinDigits {
		errors = append(errors, fmt.Sprintf("пароль должен содержать минимум %d цифр", rules.MinDigits))
	}

	if rules.RequireSpecial && specialCount < rules.MinSpecial {
		errors = append(errors, fmt.Sprintf("пароль должен содержать минимум %d специальных символов", rules.MinSpecial))
	}

	return len(errors) == 0, errors
}

// GenerateSecurePassword создает пароль с максимальными настройками безопасности
func GenerateSecurePassword(length int) (string, error) {
	if length < 12 {
		length = 12 // Минимальная безопасная длина
	}

	rules := PasswordRules{
		Length:           length,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireDigits:    true,
		RequireSpecial:   true,
		MinUppercase:     2,
		MinLowercase:     2,
		MinDigits:        2,
		MinSpecial:       2,
	}

	return GeneratePassword(rules)
}