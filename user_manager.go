package main

import (
	"fmt"
	"strings"
	"time"
)

// UserManager управляет операциями с пользователями
type UserManager struct {
	store        *UserStore
	maxAttempts  int // Максимальное количество неудачных попыток входа
}

// NewUserManager создает новый менеджер пользователей
func NewUserManager() *UserManager {
	return &UserManager{
		store:       NewUserStore(),
		maxAttempts: 3, // После 3 неудачных попыток пользователь блокируется
	}
}

// AuthResult представляет результат аутентификации
type AuthResult int

const (
	AuthSuccess AuthResult = iota
	AuthInvalidCredentials
	AuthUserBlocked
	AuthUserNotFound
)

// String возвращает строковое представление результата аутентификации
func (r AuthResult) String() string {
	switch r {
	case AuthSuccess:
		return "Успешная аутентификация"
	case AuthInvalidCredentials:
		return "Неверный логин или пароль"
	case AuthUserBlocked:
		return "Пользователь заблокирован"
	case AuthUserNotFound:
		return "Пользователь не найден"
	default:
		return "Неизвестная ошибка"
	}
}

// RegisterUser регистрирует нового пользователя
func (um *UserManager) RegisterUser(username, password string) error {
	// Проверяем, что логин не пустой
	username = strings.TrimSpace(username)
	if username == "" {
		return fmt.Errorf("логин не может быть пустым")
	}

	// Проверяем, что пользователь с таким логином не существует
	if um.store.UserExists(username) {
		return fmt.Errorf("пользователь с логином '%s' уже существует", username)
	}

	// Проверяем безопасность пароля
	isSecure, errors := IsPasswordSecure(password)
	if !isSecure {
		return fmt.Errorf("пароль не соответствует требованиям безопасности:\n- %s", 
			strings.Join(errors, "\n- "))
	}

	// Хешируем пароль
	hashedPassword, err := HashPassword(password)
	if err != nil {
		return fmt.Errorf("ошибка при создании пользователя: %v", err)
	}

	// Создаем нового пользователя
	user := &User{
		Username:       username,
		HashedPassword: hashedPassword,
		FailedAttempts: 0,
		IsBlocked:      false,
		CreatedAt:      time.Now(),
		LastLoginAt:    time.Time{}, // Будет установлено при первом входе
		BlockedAt:      time.Time{},
	}

	// Сохраняем пользователя
	um.store.SaveUser(user)
	
	return nil
}

// AuthenticateUser проверяет учетные данные пользователя
func (um *UserManager) AuthenticateUser(username, password string) (AuthResult, error) {
	username = strings.TrimSpace(username)
	
	// Находим пользователя
	user, exists := um.store.GetUser(username)
	if !exists {
		return AuthUserNotFound, nil
	}

	// Проверяем, заблокирован ли пользователь
	if user.IsBlocked {
		return AuthUserBlocked, nil
	}

	// Проверяем пароль
	if VerifyPassword(password, user.HashedPassword) {
		// Успешная аутентификация - сбрасываем счетчик неудачных попыток
		user.FailedAttempts = 0
		user.LastLoginAt = time.Now()
		um.store.SaveUser(user)
		
		return AuthSuccess, nil
	} else {
		// Неверный пароль - увеличиваем счетчик неудачных попыток
		user.FailedAttempts++
		
		// Проверяем, нужно ли блокировать пользователя
		if user.FailedAttempts >= um.maxAttempts {
			user.IsBlocked = true
			user.BlockedAt = time.Now()
		}
		
		um.store.SaveUser(user)
		
		if user.IsBlocked {
			return AuthUserBlocked, nil
		}
		
		return AuthInvalidCredentials, nil
	}
}

// ChangePassword изменяет пароль пользователя (для разблокировки)
func (um *UserManager) ChangePassword(username, newPassword string) error {
	username = strings.TrimSpace(username)
	
	// Находим пользователя
	user, exists := um.store.GetUser(username)
	if !exists {
		return fmt.Errorf("пользователь не найден")
	}

	// Проверяем безопасность нового пароля
	isSecure, errors := IsPasswordSecure(newPassword)
	if !isSecure {
		return fmt.Errorf("новый пароль не соответствует требованиям безопасности:\n- %s", 
			strings.Join(errors, "\n- "))
	}

	// Хешируем новый пароль
	hashedPassword, err := HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("ошибка при изменении пароля: %v", err)
	}

	// Обновляем пароль и разблокируем пользователя
	user.HashedPassword = hashedPassword
	user.FailedAttempts = 0
	user.IsBlocked = false
	user.BlockedAt = time.Time{}
	
	um.store.SaveUser(user)
	
	return nil
}

// GetUserStatus возвращает статус пользователя
func (um *UserManager) GetUserStatus(username string) (string, error) {
	username = strings.TrimSpace(username)
	
	user, exists := um.store.GetUser(username)
	if !exists {
		return "", fmt.Errorf("пользователь не найден")
	}

	var status strings.Builder
	status.WriteString(fmt.Sprintf("Пользователь: %s\n", user.Username))
	status.WriteString(fmt.Sprintf("Создан: %s\n", user.CreatedAt.Format("2006-01-02 15:04:05")))
	
	if !user.LastLoginAt.IsZero() {
		status.WriteString(fmt.Sprintf("Последний вход: %s\n", user.LastLoginAt.Format("2006-01-02 15:04:05")))
	} else {
		status.WriteString("Последний вход: никогда\n")
	}
	
	if user.IsBlocked {
		status.WriteString(fmt.Sprintf("Статус: ЗАБЛОКИРОВАН (с %s)\n", user.BlockedAt.Format("2006-01-02 15:04:05")))
		status.WriteString("Для разблокировки необходимо сменить пароль\n")
	} else {
		status.WriteString("Статус: активен\n")
		if user.FailedAttempts > 0 {
			status.WriteString(fmt.Sprintf("Неудачные попытки входа: %d/%d\n", user.FailedAttempts, um.maxAttempts))
		}
	}

	return status.String(), nil
}

// GetAllUsersStatus возвращает статус всех пользователей
func (um *UserManager) GetAllUsersStatus() string {
	users := um.store.GetAllUsers()
	
	if len(users) == 0 {
		return "В системе нет зарегистрированных пользователей"
	}

	var status strings.Builder
	status.WriteString(fmt.Sprintf("Всего пользователей в системе: %d\n\n", len(users)))
	
	for username, user := range users {
		status.WriteString(fmt.Sprintf("• %s", username))
		if user.IsBlocked {
			status.WriteString(" [ЗАБЛОКИРОВАН]")
		} else if user.FailedAttempts > 0 {
			status.WriteString(fmt.Sprintf(" [%d неудачных попыток]", user.FailedAttempts))
		}
		status.WriteString("\n")
	}

	return status.String()
}