package main

import (
	"time"
)

// User представляет структуру пользователя в системе
type User struct {
	Username        string    // Логин пользователя
	HashedPassword  string    // Хеш пароля с использованием bcrypt
	FailedAttempts  int       // Счетчик неудачных попыток входа
	IsBlocked       bool      // Статус блокировки пользователя
	CreatedAt       time.Time // Время создания аккаунта
	LastLoginAt     time.Time // Время последнего входа
	BlockedAt       time.Time // Время блокировки (если заблокирован)
}

// UserStore представляет хранилище пользователей (в памяти)
type UserStore struct {
	users map[string]*User // map[username]*User
}

// NewUserStore создает новое хранилище пользователей
func NewUserStore() *UserStore {
	return &UserStore{
		users: make(map[string]*User),
	}
}

// GetUser возвращает пользователя по логину
func (s *UserStore) GetUser(username string) (*User, bool) {
	user, exists := s.users[username]
	return user, exists
}

// SaveUser сохраняет пользователя в хранилище
func (s *UserStore) SaveUser(user *User) {
	s.users[user.Username] = user
}

// UserExists проверяет, существует ли пользователь с данным логином
func (s *UserStore) UserExists(username string) bool {
	_, exists := s.users[username]
	return exists
}

// GetAllUsers возвращает список всех пользователей (для отладки)
func (s *UserStore) GetAllUsers() map[string]*User {
	return s.users
}