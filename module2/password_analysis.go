package main

import (
	"fmt"
	"math"
	"strings"
)

// Структура для хранения исходных данных варианта
type PasswordTask struct {
	Variant     int     // Номер варианта
	Probability float64 // Вероятность подбора пароля (P)
	Speed       float64 // Скорость перебора в единицах времени (V)
	SpeedUnit   string  // Единица измерения скорости
	Time        float64 // Максимальный срок действия пароля (T)
	TimeUnit    string  // Единица измерения времени
}

// Структура для результатов расчёта
type PasswordAnalysis struct {
	Task           PasswordTask
	SpeedPerMinute float64 // Скорость в паролях/минуту
	TimeInMinutes  float64 // Время в минутах
	LowerBound     float64 // Нижняя граница S*
	Combinations   []AlphabetCombination
}

// Структура для комбинаций алфавита и длины
type AlphabetCombination struct {
	AlphabetSize    int     // Мощность алфавита A
	AlphabetName    string  // Описание алфавита
	MinLength       int     // Минимальная длина L
	TotalPasswords  float64 // Общее количество паролей S = A^L
	SecurityMargin  float64 // Запас безопасности
}

// Предопределённые алфавиты
var alphabets = []struct {
	Size int
	Name string
}{
	{26, "Только строчные английские буквы (a-z)"},
	{52, "Английские буквы (A-Z, a-z)"},
	{62, "Английские буквы + цифры (A-Z, a-z, 0-9)"},
	{95, "Полный ASCII набор (буквы, цифры, спецсимволы)"},
	{36, "Строчные английские буквы + цифры (a-z, 0-9)"},
	{10, "Только цифры (0-9)"},
}

// Таблица вариантов заданий
var variants = []PasswordTask{
	{1, 1e-4, 15, "паролей/мин", 2, "недели"},
	{2, 1e-5, 3, "паролей/мин", 10, "дней"},
	{3, 1e-6, 10, "паролей/мин", 5, "дней"},
	{4, 1e-7, 11, "паролей/мин", 6, "дней"},
	{5, 1e-4, 100, "паролей/день", 12, "дней"},
	{6, 1e-5, 10, "паролей/день", 1, "месяц"},
	{7, 1e-6, 20, "паролей/мин", 3, "недели"},
	{8, 1e-7, 15, "паролей/мин", 20, "дней"},
	{9, 1e-4, 3, "паролей/мин", 15, "дней"},
	{10, 1e-5, 10, "паролей/мин", 1, "неделя"},
	// ... можно добавить остальные варианты
}

func main() {
	fmt.Println("=== КОЛИЧЕСТВЕННАЯ ОЦЕНКА СТОЙКОСТИ ПАРОЛЕЙ ===")
	fmt.Println()

	// Выбор варианта
	var variantNum int
	fmt.Print("Введите номер варианта (1-30): ")
	fmt.Scanf("%d", &variantNum)

	if variantNum < 1 || variantNum > len(variants) {
		fmt.Printf("❌ Вариант %d не найден в таблице\n", variantNum)
		fmt.Println("Доступные варианты:")
		for _, v := range variants {
			fmt.Printf("Вариант %d: P=%.0e, V=%.0f %s, T=%.0f %s\n", 
				v.Variant, v.Probability, v.Speed, v.SpeedUnit, v.Time, v.TimeUnit)
		}
		return
	}

	task := variants[variantNum-1]
	fmt.Printf("\n📋 Выбран вариант %d:\n", task.Variant)
	fmt.Printf("   P = %.0e (вероятность подбора)\n", task.Probability)
	fmt.Printf("   V = %.0f %s (скорость перебора)\n", task.Speed, task.SpeedUnit)
	fmt.Printf("   T = %.0f %s (срок действия пароля)\n", task.Time, task.TimeUnit)

	// Выполняем анализ
	analysis := analyzePasswordSecurity(task)
	
	// Выводим результаты
	printResults(analysis)

	fmt.Println("\n=== ГЕНЕРАТОР ПАРОЛЕЙ ===")
	generatePasswordExample(analysis)
}

// Функция анализа безопасности пароля
func analyzePasswordSecurity(task PasswordTask) PasswordAnalysis {
	analysis := PasswordAnalysis{Task: task}
	
	// Конвертируем скорость в пароли/минуту
	analysis.SpeedPerMinute = convertToPerMinute(task.Speed, task.SpeedUnit)
	
	// Конвертируем время в минуты
	analysis.TimeInMinutes = convertToMinutes(task.Time, task.TimeUnit)
	
	// Вычисляем нижнюю границу S*
	analysis.LowerBound = math.Ceil((analysis.SpeedPerMinute * analysis.TimeInMinutes) / task.Probability)
	
	// Ищем подходящие комбинации алфавита и длины
	analysis.Combinations = findAlphabetCombinations(analysis.LowerBound)
	
	return analysis
}

// Конвертация скорости в пароли/минуту
func convertToPerMinute(speed float64, unit string) float64 {
	switch {
	case strings.Contains(unit, "мин"):
		return speed
	case strings.Contains(unit, "день"):
		return speed / (24 * 60) // паролей в день -> паролей в минуту
	case strings.Contains(unit, "час"):
		return speed / 60 // паролей в час -> паролей в минуту
	default:
		return speed // по умолчанию считаем что уже в минутах
	}
}

// Конвертация времени в минуты
func convertToMinutes(time float64, unit string) float64 {
	switch {
	case strings.Contains(unit, "мин"):
		return time
	case strings.Contains(unit, "час"):
		return time * 60
	case strings.Contains(unit, "день") || strings.Contains(unit, "дн"):
		return time * 24 * 60
	case strings.Contains(unit, "неделя") || strings.Contains(unit, "нед"):
		return time * 7 * 24 * 60
	case strings.Contains(unit, "месяц"):
		return time * 30 * 24 * 60 // примерно 30 дней
	default:
		return time
	}
}

// Поиск подходящих комбинаций алфавита и длины
func findAlphabetCombinations(lowerBound float64) []AlphabetCombination {
	var combinations []AlphabetCombination
	
	for _, alphabet := range alphabets {
		// Находим минимальную длину для данного алфавита
		minLength := int(math.Ceil(math.Log(lowerBound) / math.Log(float64(alphabet.Size))))
		
		if minLength > 0 && minLength <= 20 { // разумные ограничения на длину
			totalPasswords := math.Pow(float64(alphabet.Size), float64(minLength))
			securityMargin := totalPasswords / lowerBound
			
			combination := AlphabetCombination{
				AlphabetSize:   alphabet.Size,
				AlphabetName:   alphabet.Name,
				MinLength:      minLength,
				TotalPasswords: totalPasswords,
				SecurityMargin: securityMargin,
			}
			
			combinations = append(combinations, combination)
		}
	}
	
	return combinations
}

// Вывод результатов анализа
func printResults(analysis PasswordAnalysis) {
	fmt.Println("\n РЕЗУЛЬТАТЫ АНАЛИЗА:")
	fmt.Printf("   Скорость перебора: %.2f паролей/мин\n", analysis.SpeedPerMinute)
	fmt.Printf("   Время действия: %.0f минут (%.2f дней)\n", 
		analysis.TimeInMinutes, analysis.TimeInMinutes/(24*60))
	
	fmt.Printf("\n Нижняя граница S*: %.2e\n", analysis.LowerBound)
	fmt.Printf("   (минимальное количество возможных паролей)\n")
	
	fmt.Println("\n РЕКОМЕНДУЕМЫЕ ПАРАМЕТРЫ ПАРОЛЕЙ:")
	fmt.Println("┌─────┬──────────────────────────────────────────┬────────┬─────────────┬─────────────┐")
	fmt.Println("│  A  │               Алфавит                    │   L    │   Всего     │   Запас     │")
	fmt.Println("│     │                                          │        │  паролей    │ безопасности│")
	fmt.Println("├─────┼──────────────────────────────────────────┼────────┼─────────────┼─────────────┤")
	
	for _, combo := range analysis.Combinations {
		fmt.Printf("│ %3d │ %-40s │ %6d │ %11.2e │ %11.2f │\n",
			combo.AlphabetSize,
			combo.AlphabetName,
			combo.MinLength,
			combo.TotalPasswords,
			combo.SecurityMargin)
	}
	fmt.Println("└─────┴──────────────────────────────────────────┴────────┴─────────────┴─────────────┘")
	
	if len(analysis.Combinations) > 0 {
		best := analysis.Combinations[0]
		for _, combo := range analysis.Combinations {
			if combo.MinLength < best.MinLength {
				best = combo
			}
		}
		
		fmt.Printf("\n ОПТИМАЛЬНЫЙ ВЫБОР:\n")
		fmt.Printf("   Алфавит: %s (A = %d)\n", best.AlphabetName, best.AlphabetSize)
		fmt.Printf("   Минимальная длина пароля: %d символов\n", best.MinLength)
		fmt.Printf("   Запас безопасности: %.2f раз\n", best.SecurityMargin)
	}
}

// Демонстрация генерации пароля
func generatePasswordExample(analysis PasswordAnalysis) {
	if len(analysis.Combinations) == 0 {
		fmt.Println(" Не удалось найти подходящие параметры для генерации")
		return
	}
	
	// Выбираем оптимальную комбинацию
	best := analysis.Combinations[0]
	for _, combo := range analysis.Combinations {
		if combo.AlphabetSize == 62 { // предпочитаем буквы + цифры
			best = combo
			break
		}
	}
	
	fmt.Printf(" Пример генерации пароля (A=%d, L=%d):\n", 
		best.AlphabetSize, best.MinLength)
	
	// Генерируем несколько примеров паролей
	for i := 1; i <= 5; i++ {
		password := generateSecurePassword(best.AlphabetSize, best.MinLength)
		fmt.Printf("   %d. %s\n", i, password)
	}
	
	fmt.Println("\n Рекомендации по использованию:")
	fmt.Println("   • Используйте один из сгенерированных паролей")
	fmt.Println("   • Не записывайте пароль в открытом виде")
	fmt.Println("   • Меняйте пароль в соответствии с установленным сроком")
	fmt.Printf("   • Максимальный срок использования: %.0f %s\n", 
		analysis.Task.Time, analysis.Task.TimeUnit)
}

// Простой генератор паролей для демонстрации
func generateSecurePassword(alphabetSize, length int) string {
	var charset string
	
	switch alphabetSize {
	case 10:
		charset = "0123456789"
	case 26:
		charset = "abcdefghijklmnopqrstuvwxyz"
	case 36:
		charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	case 52:
		charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	case 62:
		charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	case 95:
		charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
	default:
		charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	}
	
	// Простая псевдослучайная генерация (для демонстрации)
	password := make([]byte, length)
	for i := 0; i < length; i++ {
		// Используем простую формулу для демонстрации
		// В реальной системе следует использовать crypto/rand
		idx := (i*17 + 42) % len(charset)
		password[i] = charset[idx]
	}
	
	return string(password)
}

// Функция для интерактивного расчёта произвольных параметров
func customCalculation() {
	fmt.Println("\n=== ПОЛЬЗОВАТЕЛЬСКИЙ РАСЧЁТ ===")
	
	var P, V, T float64
	var speedUnit, timeUnit string
	
	fmt.Print("Введите вероятность подбора P (например, 1e-6): ")
	fmt.Scanf("%f", &P)
	
	fmt.Print("Введите скорость перебора V: ")
	fmt.Scanf("%f", &V)
	
	fmt.Print("Единица измерения скорости (паролей/мин, паролей/день): ")
	fmt.Scanf("%s", &speedUnit)
	
	fmt.Print("Введите время действия пароля T: ")
	fmt.Scanf("%f", &T)
	
	fmt.Print("Единица измерения времени (дней, недель, месяц): ")
	fmt.Scanf("%s", &timeUnit)
	
	task := PasswordTask{
		Variant:     0,
		Probability: P,
		Speed:       V,
		SpeedUnit:   speedUnit,
		Time:        T,
		TimeUnit:    timeUnit,
	}
	
	analysis := analyzePasswordSecurity(task)
	printResults(analysis)
}