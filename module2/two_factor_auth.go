package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Структура пользователя с поддержкой 2FA
type User2FA struct {
	Username     string    // Логин пользователя
	PasswordHash string    // Хеш пароля
	TotpSecret   string    // Секретный ключ для TOTP
	BackupCodes  []string  // Резервные коды
	Is2FAEnabled bool      // Включена ли двухфакторная аутентификация
	CreatedAt    time.Time // Время создания аккаунта
	LastLogin    time.Time // Время последнего входа
}

// Хранилище пользователей
type User2FAStore struct {
	users map[string]*User2FA
}

// Менеджер двухфакторной аутентификации
type TwoFactorAuth struct {
	store         *User2FAStore
	codeLifetime  int // Время жизни TOTP кода в секундах
	backupCodes   int // Количество резервных кодов
}

// Результат аутентификации
type AuthResult2FA struct {
	Success      bool
	Message      string
	RequiresTOTP bool // Требуется ввод TOTP кода
	User         *User2FA
}

func main() {
	fmt.Println("=== СИСТЕМА ДВУХФАКТОРНОЙ АУТЕНТИФИКАЦИИ ===")
	fmt.Println()

	// Инициализация системы
	auth := NewTwoFactorAuth()
	scanner := bufio.NewScanner(os.Stdin)

	for {
		showMenu()
		
		fmt.Print("Выберите действие (1-8): ")
		if !scanner.Scan() {
			break
		}
		
		choice := strings.TrimSpace(scanner.Text())
		fmt.Println()

		switch choice {
		case "1":
			registerUser2FA(auth, scanner)
		case "2":
			loginUser2FA(auth, scanner)
		case "3":
			enable2FA(auth, scanner)
		case "4":
			disable2FA(auth, scanner)
		case "5":
			generateBackupCodes(auth, scanner)
		case "6":
			showUserInfo(auth, scanner)
		case "7":
			demonstrate2FA()
		case "8":
			fmt.Println("Спасибо за использование системы 2FA!")
			return
		default:
			fmt.Println("❌ Неверный выбор. Пожалуйста, выберите от 1 до 8.")
		}

		fmt.Println()
		fmt.Print("Нажмите Enter для продолжения...")
		scanner.Scan()
		fmt.Println()
	}
}

func NewTwoFactorAuth() *TwoFactorAuth {
	return &TwoFactorAuth{
		store: &User2FAStore{
			users: make(map[string]*User2FA),
		},
		codeLifetime: 30, // 30 секунд для TOTP
		backupCodes:  10, // 10 резервных кодов
	}
}

func showMenu() {
	fmt.Println("┌─────────────────────────────────────────────┐")
	fmt.Println("│         ДВУХФАКТОРНАЯ АУТЕНТИФИКАЦИЯ        │")
	fmt.Println("├─────────────────────────────────────────────┤")
	fmt.Println("│ 1. Регистрация пользователя                 │")
	fmt.Println("│ 2. Вход в систему                           │")
	fmt.Println("│ 3. Включить 2FA                             │")
	fmt.Println("│ 4. Отключить 2FA                            │")
	fmt.Println("│ 5. Сгенерировать резервные коды             │")
	fmt.Println("│ 6. Информация о пользователе                │")
	fmt.Println("│ 7. Демонстрация алгоритма TOTP              │")
	fmt.Println("│ 8. Выход                                    │")
	fmt.Println("└─────────────────────────────────────────────┘")
}

// Регистрация пользователя
func registerUser2FA(auth *TwoFactorAuth, scanner *bufio.Scanner) {
	fmt.Println("=== РЕГИСТРАЦИЯ ПОЛЬЗОВАТЕЛЯ ===")
	
	fmt.Print("Логин: ")
	if !scanner.Scan() {
		return
	}
	username := strings.TrimSpace(scanner.Text())

	if username == "" {
		fmt.Println("❌ Логин не может быть пустым")
		return
	}

	if _, exists := auth.store.users[username]; exists {
		fmt.Println("❌ Пользователь уже существует")
		return
	}

	fmt.Print("Пароль: ")
	password := readPasswordSimple(scanner)

	if len(password) < 6 {
		fmt.Println("❌ Пароль должен содержать минимум 6 символов")
		return
	}

	// Хешируем пароль
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Printf("❌ Ошибка при создании пароля: %v\n", err)
		return
	}

	// Создаем пользователя
	user := &User2FA{
		Username:     username,
		PasswordHash: string(hashedPassword),
		TotpSecret:   "",
		BackupCodes:  []string{},
		Is2FAEnabled: false,
		CreatedAt:    time.Now(),
		LastLogin:    time.Time{},
	}

	auth.store.users[username] = user
	fmt.Printf("✅ Пользователь '%s' успешно зарегистрирован!\n", username)
	fmt.Println("💡 Рекомендуется включить двухфакторную аутентификацию (пункт 3)")
}

// Вход в систему
func loginUser2FA(auth *TwoFactorAuth, scanner *bufio.Scanner) {
	fmt.Println("=== ВХОД В СИСТЕМУ ===")
	
	fmt.Print("Логин: ")
	if !scanner.Scan() {
		return
	}
	username := strings.TrimSpace(scanner.Text())

	fmt.Print("Пароль: ")
	password := readPasswordSimple(scanner)

	// Первый фактор - проверка пароля
	result := auth.authenticateFirstFactor(username, password)
	
	if !result.Success {
		fmt.Printf("❌ %s\n", result.Message)
		return
	}

	// Если 2FA отключена, вход успешен
	if !result.RequiresTOTP {
		fmt.Printf("✅ Добро пожаловать, %s!\n", username)
		result.User.LastLogin = time.Now()
		return
	}

	// Второй фактор - TOTP код
	fmt.Println("🔐 Требуется код двухфакторной аутентификации")
	fmt.Print("Введите 6-значный код или резервный код: ")
	if !scanner.Scan() {
		return
	}
	code := strings.TrimSpace(scanner.Text())

	// Проверяем TOTP код или резервный код
	if auth.verifySecondFactor(result.User, code) {
		fmt.Printf("✅ Добро пожаловать, %s!\n", username)
		result.User.LastLogin = time.Now()
	} else {
		fmt.Println("❌ Неверный код аутентификации")
	}
}

// Включение 2FA
func enable2FA(auth *TwoFactorAuth, scanner *bufio.Scanner) {
	fmt.Println("=== ВКЛЮЧЕНИЕ ДВУХФАКТОРНОЙ АУТЕНТИФИКАЦИИ ===")
	
	user := authenticateUser(auth, scanner)
	if user == nil {
		return
	}

	if user.Is2FAEnabled {
		fmt.Println("ℹ️  Двухфакторная аутентификация уже включена")
		return
	}

	// Генерируем секретный ключ
	secret := generateTOTPSecret()
	user.TotpSecret = secret

	// Генерируем резервные коды
	user.BackupCodes = generateBackupCodesList(auth.backupCodes)

	fmt.Printf("🔑 Секретный ключ TOTP: %s\n", secret)
	fmt.Println("📱 Добавьте этот ключ в ваше приложение аутентификатор")
	fmt.Println("   (Google Authenticator, Authy, и т.д.)")
	fmt.Println()

	// Показываем резервные коды
	fmt.Println("🆘 РЕЗЕРВНЫЕ КОДЫ (сохраните в безопасном месте!):")
	for i, code := range user.BackupCodes {
		fmt.Printf("   %2d. %s\n", i+1, code)
	}
	fmt.Println()

	// Подтверждение настройки
	fmt.Print("Введите код из приложения для подтверждения: ")
	if !scanner.Scan() {
		return
	}
	code := strings.TrimSpace(scanner.Text())

	if auth.verifyTOTPCode(secret, code) {
		user.Is2FAEnabled = true
		fmt.Println("✅ Двухфакторная аутентификация успешно включена!")
	} else {
		fmt.Println("❌ Неверный код. 2FA не была включена.")
		user.TotpSecret = ""
		user.BackupCodes = []string{}
	}
}

// Отключение 2FA
func disable2FA(auth *TwoFactorAuth, scanner *bufio.Scanner) {
	fmt.Println("=== ОТКЛЮЧЕНИЕ ДВУХФАКТОРНОЙ АУТЕНТИФИКАЦИИ ===")
	
	user := authenticateUser(auth, scanner)
	if user == nil {
		return
	}

	if !user.Is2FAEnabled {
		fmt.Println("ℹ️  Двухфакторная аутентификация не включена")
		return
	}

	fmt.Print("Введите текущий код 2FA для подтверждения: ")
	if !scanner.Scan() {
		return
	}
	code := strings.TrimSpace(scanner.Text())

	if auth.verifySecondFactor(user, code) {
		user.Is2FAEnabled = false
		user.TotpSecret = ""
		user.BackupCodes = []string{}
		fmt.Println("✅ Двухфакторная аутентификация отключена")
	} else {
		fmt.Println("❌ Неверный код. 2FA не была отключена.")
	}
}

// Генерация новых резервных кодов
func generateBackupCodes(auth *TwoFactorAuth, scanner *bufio.Scanner) {
	fmt.Println("=== ГЕНЕРАЦИЯ НОВЫХ РЕЗЕРВНЫХ КОДОВ ===")
	
	user := authenticateUser(auth, scanner)
	if user == nil {
		return
	}

	if !user.Is2FAEnabled {
		fmt.Println("❌ Сначала включите двухфакторную аутентификацию")
		return
	}

	user.BackupCodes = generateBackupCodesList(auth.backupCodes)
	
	fmt.Println("🆘 НОВЫЕ РЕЗЕРВНЫЕ КОДЫ:")
	for i, code := range user.BackupCodes {
		fmt.Printf("   %2d. %s\n", i+1, code)
	}
	fmt.Println()
	fmt.Println("⚠️  Старые резервные коды больше не действительны!")
	fmt.Println("💾 Сохраните новые коды в безопасном месте")
}

// Показ информации о пользователе
func showUserInfo(auth *TwoFactorAuth, scanner *bufio.Scanner) {
	fmt.Println("=== ИНФОРМАЦИЯ О ПОЛЬЗОВАТЕЛЕ ===")
	
	user := authenticateUser(auth, scanner)
	if user == nil {
		return
	}

	fmt.Printf("👤 Пользователь: %s\n", user.Username)
	fmt.Printf("📅 Создан: %s\n", user.CreatedAt.Format("2006-01-02 15:04:05"))
	
	if !user.LastLogin.IsZero() {
		fmt.Printf("🕒 Последний вход: %s\n", user.LastLogin.Format("2006-01-02 15:04:05"))
	} else {
		fmt.Println("🕒 Последний вход: никогда")
	}

	if user.Is2FAEnabled {
		fmt.Println("🔐 Двухфакторная аутентификация: ✅ ВКЛЮЧЕНА")
		fmt.Printf("🔑 Секретный ключ: %s\n", user.TotpSecret)
		fmt.Printf("🆘 Резервных кодов: %d\n", len(user.BackupCodes))
	} else {
		fmt.Println("🔐 Двухфакторная аутентификация: ❌ ОТКЛЮЧЕНА")
	}
}

// Демонстрация алгоритма TOTP
func demonstrate2FA() {
	fmt.Println("=== ДЕМОНСТРАЦИЯ АЛГОРИТМА TOTP ===")
	
	// Генерируем тестовый секрет
	secret := generateTOTPSecret()
	fmt.Printf("🔑 Тестовый секрет: %s\n", secret)
	fmt.Println()

	fmt.Println("📊 Генерация TOTP кодов по времени:")
	fmt.Println("┌────────────────────┬──────────┬─────────────────────┐")
	fmt.Println("│      Время         │   Код    │    Время до смены   │")
	fmt.Println("├────────────────────┼──────────┼─────────────────────┤")
	
	for i := 0; i < 10; i++ {
		currentTime := time.Now().Add(time.Duration(i*30) * time.Second)
		code := generateTOTPCode(secret, currentTime)
		timeLeft := 30 - (currentTime.Unix() % 30)
		
		fmt.Printf("│ %s │ %s │ %19d │\n", 
			currentTime.Format("2006-01-02 15:04:05"), 
			code, 
			timeLeft)
		
		time.Sleep(100 * time.Millisecond) // Небольшая задержка для наглядности
	}
	fmt.Println("└────────────────────┴──────────┴─────────────────────┘")
	
	fmt.Println("\n🔍 Алгоритм TOTP:")
	fmt.Println("   1. Берем текущее время Unix")
	fmt.Println("   2. Делим на интервал (30 сек)")
	fmt.Println("   3. Вычисляем HMAC-SHA256 от секрета и времени")
	fmt.Println("   4. Извлекаем 6-значный код")
	fmt.Println("   5. Код действителен только в текущем интервале")
}

// Функции аутентификации

func (auth *TwoFactorAuth) authenticateFirstFactor(username, password string) AuthResult2FA {
	user, exists := auth.store.users[username]
	if !exists {
		return AuthResult2FA{false, "Пользователь не найден", false, nil}
	}

	err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		return AuthResult2FA{false, "Неверный пароль", false, nil}
	}

	return AuthResult2FA{true, "Первый фактор пройден", user.Is2FAEnabled, user}
}

func (auth *TwoFactorAuth) verifySecondFactor(user *User2FA, code string) bool {
	// Проверяем TOTP код
	if len(code) == 6 && auth.verifyTOTPCode(user.TotpSecret, code) {
		return true
	}

	// Проверяем резервные коды
	for i, backupCode := range user.BackupCodes {
		if code == backupCode {
			// Удаляем использованный резервный код
			user.BackupCodes = append(user.BackupCodes[:i], user.BackupCodes[i+1:]...)
			return true
		}
	}

	return false
}

// Функции генерации и проверки TOTP

func generateTOTPSecret() string {
	// Генерируем 16-байтный случайный секрет
	bytes := make([]byte, 16)
	for i := range bytes {
		randomBig, _ := rand.Int(rand.Reader, big.NewInt(256))
		bytes[i] = byte(randomBig.Int64())
	}
	
	// Конвертируем в hex строку
	secret := fmt.Sprintf("%x", bytes)
	return secret
}

func generateTOTPCode(secret string, timestamp time.Time) string {
	// Упрощенный алгоритм TOTP для демонстрации
	timeCounter := timestamp.Unix() / 30 // 30-секундные интервалы
	
	// Создаем хеш на основе секрета и времени
	hasher := sha256.New()
	hasher.Write([]byte(secret))
	hasher.Write([]byte(fmt.Sprintf("%d", timeCounter)))
	hash := hasher.Sum(nil)
	
	// Извлекаем 6-значный код
	code := 0
	for i := 0; i < 4; i++ {
		code = (code << 8) | int(hash[i])
	}
	code = code % 1000000
	
	return fmt.Sprintf("%06d", code)
}

func (auth *TwoFactorAuth) verifyTOTPCode(secret, inputCode string) bool {
	currentTime := time.Now()
	
	// Проверяем коды в окне ±1 интервал для компенсации расхождения времени
	for offset := -1; offset <= 1; offset++ {
		testTime := currentTime.Add(time.Duration(offset*30) * time.Second)
		expectedCode := generateTOTPCode(secret, testTime)
		
		if inputCode == expectedCode {
			return true
		}
	}
	
	return false
}

// Функции для резервных кодов

func generateBackupCodesList(count int) []string {
	codes := make([]string, count)
	
	for i := 0; i < count; i++ {
		codes[i] = generateBackupCode()
	}
	
	return codes
}

func generateBackupCode() string {
	// Генерируем 8-символьный код из цифр и букв
	charset := "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	code := make([]byte, 8)
	
	for i := range code {
		randomBig, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		code[i] = charset[randomBig.Int64()]
	}
	
	return string(code)
}

// Вспомогательные функции

func authenticateUser(auth *TwoFactorAuth, scanner *bufio.Scanner) *User2FA {
	fmt.Print("Логин: ")
	if !scanner.Scan() {
		return nil
	}
	username := strings.TrimSpace(scanner.Text())

	fmt.Print("Пароль: ")
	password := readPasswordSimple(scanner)

	result := auth.authenticateFirstFactor(username, password)
	if !result.Success {
		fmt.Printf("❌ %s\n", result.Message)
		return nil
	}

	return result.User
}

func readPasswordSimple(scanner *bufio.Scanner) string {
	// Упрощенная версия чтения пароля для совместимости
	if !scanner.Scan() {
		return ""
	}
	return strings.TrimSpace(scanner.Text())
}