package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/term"
)

func main() {
	fmt.Println("=== СИСТЕМА УПРАВЛЕНИЯ ПОЛЬЗОВАТЕЛЯМИ ===")
	fmt.Println("Версия 1.0")
	fmt.Println()

	userManager := NewUserManager()
	scanner := bufio.NewScanner(os.Stdin)

	for {
		showMainMenu()
		
		fmt.Print("Выберите действие (1-8): ")
		if !scanner.Scan() {
			break
		}
		
		choice := strings.TrimSpace(scanner.Text())
		fmt.Println()

		switch choice {
		case "1":
			registerUser(userManager, scanner)
		case "2":
			authenticateUser(userManager, scanner)
		case "3":
			changeUserPassword(userManager, scanner)
		case "4":
			showUserStatus(userManager, scanner)
		case "5":
			showAllUsers(userManager)
		case "6":
			generatePasswordDemo()
		case "7":
			showPasswordRules()
		case "8":
			fmt.Println("Спасибо за использование системы!")
			return
		default:
			fmt.Println(" Неверный выбор. Пожалуйста, выберите от 1 до 8.")
		}

		fmt.Println()
		fmt.Print("Нажмите Enter для продолжения...")
		scanner.Scan()
		fmt.Println()
	}
}

func showMainMenu() {
	fmt.Println("┌─────────────────────────────────────────┐")
	fmt.Println("│              ГЛАВНОЕ МЕНЮ               │")
	fmt.Println("├─────────────────────────────────────────┤")
	fmt.Println("│ 1. Регистрация пользователя             │")
	fmt.Println("│ 2. Вход в систему                       │")
	fmt.Println("│ 3. Смена пароля (разблокировка)         │")
	fmt.Println("│ 4. Статус пользователя                  │")
	fmt.Println("│ 5. Список всех пользователей            │")
	fmt.Println("│ 6. Генерация безопасного пароля         │")
	fmt.Println("│ 7. Правила создания паролей             │")
	fmt.Println("│ 8. Выход                                │")
	fmt.Println("└─────────────────────────────────────────┘")
}

func registerUser(userManager *UserManager, scanner *bufio.Scanner) {
	fmt.Println("=== РЕГИСТРАЦИЯ НОВОГО ПОЛЬЗОВАТЕЛЯ ===")
	
	// Ввод логина
	fmt.Print("Введите логин: ")
	if !scanner.Scan() {
		return
	}
	username := strings.TrimSpace(scanner.Text())

	if username == "" {
		fmt.Println(" Логин не может быть пустым.")
		return
	}

	// Ввод пароля
	fmt.Print("Введите пароль: ")
	password, err := readPassword()
	if err != nil {
		fmt.Printf(" Ошибка при вводе пароля: %v\n", err)
		return
	}

	// Попытка регистрации
	err = userManager.RegisterUser(username, password)
	if err != nil {
		fmt.Printf(" Ошибка регистрации: %v\n", err)
		return
	}

	fmt.Printf("✅ Пользователь '%s' успешно зарегистрирован!\n", username)
}

func authenticateUser(userManager *UserManager, scanner *bufio.Scanner) {
	fmt.Println("=== ВХОД В СИСТЕМУ ===")
	
	// Ввод логина
	fmt.Print("Логин: ")
	if !scanner.Scan() {
		return
	}
	username := strings.TrimSpace(scanner.Text())

	if username == "" {
		fmt.Println(" Логин не может быть пустым.")
		return
	}

	// Ввод пароля
	fmt.Print("Пароль: ")
	password, err := readPassword()
	if err != nil {
		fmt.Printf(" Ошибка при вводе пароля: %v\n", err)
		return
	}

	// Попытка аутентификации
	result, err := userManager.AuthenticateUser(username, password)
	if err != nil {
		fmt.Printf(" Ошибка при входе: %v\n", err)
		return
	}

	switch result {
	case AuthSuccess:
		fmt.Printf(" Добро пожаловать, %s!\n", username)
	case AuthUserNotFound:
		fmt.Println(" Пользователь не найден.")
	case AuthInvalidCredentials:
		fmt.Println(" Неверный логин или пароль.")
		// Показываем статус после неудачной попытки
		if status, err := userManager.GetUserStatus(username); err == nil {
			fmt.Println("\n Текущий статус:")
			fmt.Print(status)
		}
	case AuthUserBlocked:
		fmt.Println("	Пользователь заблокирован после превышения лимита неудачных попыток входа.")
		fmt.Println("   Для разблокировки используйте опцию смены пароля.")
	}
}

func changeUserPassword(userManager *UserManager, scanner *bufio.Scanner) {
	fmt.Println("=== СМЕНА ПАРОЛЯ (РАЗБЛОКИРОВКА) ===")
	
	// Ввод логина
	fmt.Print("Логин пользователя: ")
	if !scanner.Scan() {
		return
	}
	username := strings.TrimSpace(scanner.Text())

	if username == "" {
		fmt.Println(" Логин не может быть пустым.")
		return
	}

	// Ввод нового пароля
	fmt.Print("Новый пароль: ")
	newPassword, err := readPassword()
	if err != nil {
		fmt.Printf(" Ошибка при вводе пароля: %v\n", err)
		return
	}

	// Подтверждение пароля
	fmt.Print("Подтвердите новый пароль: ")
	confirmPassword, err := readPassword()
	if err != nil {
		fmt.Printf(" Ошибка при вводе пароля: %v\n", err)
		return
	}

	if newPassword != confirmPassword {
		fmt.Println(" Пароли не совпадают.")
		return
	}

	// Попытка смены пароля
	err = userManager.ChangePassword(username, newPassword)
	if err != nil {
		fmt.Printf(" Ошибка при смене пароля: %v\n", err)
		return
	}

	fmt.Printf("Пароль для пользователя '%s' успешно изменен!\n", username)
	fmt.Println("   Пользователь разблокирован и может войти в систему.")
}

func showUserStatus(userManager *UserManager, scanner *bufio.Scanner) {
	fmt.Println("=== СТАТУС ПОЛЬЗОВАТЕЛЯ ===")
	
	fmt.Print("Введите логин пользователя: ")
	if !scanner.Scan() {
		return
	}
	username := strings.TrimSpace(scanner.Text())

	if username == "" {
		fmt.Println(" Логин не может быть пустым.")
		return
	}

	status, err := userManager.GetUserStatus(username)
	if err != nil {
		fmt.Printf(" %v\n", err)
		return
	}

	fmt.Println("\n Статус пользователя:")
	fmt.Print(status)
}

func showAllUsers(userManager *UserManager) {
	fmt.Println("=== СПИСОК ВСЕХ ПОЛЬЗОВАТЕЛЕЙ ===")
	status := userManager.GetAllUsersStatus()
	fmt.Println(status)
}

func generatePasswordDemo() {
	fmt.Println("=== ГЕНЕРАЦИЯ БЕЗОПАСНОГО ПАРОЛЯ ===")
	
	scanner := bufio.NewScanner(os.Stdin)
	
	fmt.Print("Введите желаемую длину пароля (минимум 12, по умолчанию 16): ")
	scanner.Scan()
	lengthStr := strings.TrimSpace(scanner.Text())
	
	length := 16 // по умолчанию
	if lengthStr != "" {
		if parsedLength, err := strconv.Atoi(lengthStr); err == nil && parsedLength >= 12 {
			length = parsedLength
		} else {
			fmt.Println("  Использую длину по умолчанию (16 символов)")
		}
	}

	// Генерируем несколько вариантов паролей
	fmt.Printf("\n Сгенерированные пароли (длина: %d символов):\n\n", length)
	
	for i := 1; i <= 5; i++ {
		password, err := GenerateSecurePassword(length)
		if err != nil {
			fmt.Printf(" Ошибка при генерации пароля: %v\n", err)
			return
		}
		fmt.Printf("%d. %s\n", i, password)
	}

	fmt.Println("\n💡 Рекомендации:")
	fmt.Println("   • Сохраните выбранный пароль в безопасном месте")
	fmt.Println("   • Не используйте один пароль для разных аккаунтов")
	fmt.Println("   • Регулярно меняйте пароли")
}

func showPasswordRules() {
	fmt.Println("=== ПРАВИЛА СОЗДАНИЯ БЕЗОПАСНЫХ ПАРОЛЕЙ ===")
	
	rules := DefaultPasswordRules()
	
	fmt.Printf(" Требования к паролям в системе:\n\n")
	fmt.Printf("• Минимальная длина: %d символов\n", rules.Length)
	if rules.RequireUppercase {
		fmt.Printf("• Заглавные буквы (A-Z): минимум %d\n", rules.MinUppercase)
	}
	if rules.RequireLowercase {
		fmt.Printf("• Строчные буквы (a-z): минимум %d\n", rules.MinLowercase)
	}
	if rules.RequireDigits {
		fmt.Printf("• Цифры (0-9): минимум %d\n", rules.MinDigits)
	}
	if rules.RequireSpecial {
		fmt.Printf("• Специальные символы (!@#$%%^&*()_+-=[]{}|;:,.<>?): минимум %d\n", rules.MinSpecial)
	}

	fmt.Println("\n Принципы безопасности:")
	fmt.Println("   • Используйте уникальные пароли для каждого аккаунта")
	fmt.Println("   • Избегайте словарных слов и личной информации")
	fmt.Println("   • Используйте комбинации разных типов символов")
	fmt.Println("   • Регулярно обновляйте пароли")
	fmt.Println("   • Используйте менеджеры паролей для хранения")

	fmt.Println("\n Примеры надежных паролей:")
	for i := 1; i <= 3; i++ {
		if password, err := GenerateSecurePassword(12); err == nil {
			fmt.Printf("   %d. %s\n", i, password)
		}
	}
}

// readPassword безопасно читает пароль без отображения символов на экране
func readPassword() (string, error) {
	fd := int(syscall.Stdin)
	if !term.IsTerminal(fd) {
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			return scanner.Text(), nil
		}
		return "", scanner.Err()
	}

	bytePassword, err := term.ReadPassword(fd)
	if err != nil {
		return "", err
	}
	fmt.Println() 

	return string(bytePassword), nil
}