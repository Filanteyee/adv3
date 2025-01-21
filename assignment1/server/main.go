package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Request and Response payloads
type RequestPayload struct {
	Message string `json:"message"`
}

type ResponsePayload struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

// Database models
type User struct {
	gorm.Model
	Email    string
	Password string
}

type Booking struct {
	gorm.Model
	Date  string
	Time  string
	Field string
}

// Global database instance and logger
var db *gorm.DB
var logger = logrus.New()

// Initialize rate limiter
var limiter = rate.NewLimiter(2, 5) // 2 requests per second with a burst of 5

// Initialize the database
func initDB() {
	// Update the DSN with Railway database details
	// Using the new host `autorack.proxy.rlwy.net` and the provided credentials
	dsn := fmt.Sprintf(
		"host=autorack.proxy.rlwy.net user=postgres password=nLoqkqtqDyyeXELSjyRVGTRhEKjrhqCn dbname=railway port=41607 sslmode=disable",
	)

	var err error
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		logger.WithField("error", err).Fatal("Не удалось подключиться к базе данных")
	}

	// Migrate models
	db.AutoMigrate(&User{}, &Booking{})
	logger.Info("Успешно подключено к базе данных и выполнена миграция")
}

// Enable CORS for HTTP responses
func enableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Middleware for rate limiting
func rateLimited(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			logger.WithFields(logrus.Fields{
				"action":      "rate_limit",
				"client_ip":   r.RemoteAddr,
				"status_code": http.StatusTooManyRequests,
			}).Warn("Rate limit exceeded")
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

// Log requests with structured data
func logRequest(action string, r *http.Request, extraFields logrus.Fields) {
	fields := logrus.Fields{
		"action":    action,
		"client_ip": r.RemoteAddr,
		"timestamp": time.Now(),
	}
	for k, v := range extraFields {
		fields[k] = v
	}
	logger.WithFields(fields).Info("Request processed")
}

// Error handler utility
func handleError(w http.ResponseWriter, err error, message string, statusCode int) {
	logger.WithFields(logrus.Fields{
		"error":       err.Error(),
		"status_code": statusCode,
	}).Error(message)
	http.Error(w, message, statusCode)
}

// Handle user authentication and registration
func handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Login logic
		var user User
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&user)
		defer r.Body.Close()
		if err != nil || user.Email == "" || user.Password == "" {
			handleError(w, fmt.Errorf("invalid login data"), "Некорректные данные для авторизации", http.StatusBadRequest)
			return
		}

		var existingUser User
		if err := db.Where("email = ?", user.Email).First(&existingUser).Error; err != nil {
			handleError(w, fmt.Errorf("user not found"), "Пользователь не найден", http.StatusUnauthorized)
			return
		}

		if existingUser.Password != user.Password {
			handleError(w, fmt.Errorf("invalid password"), "Неверный пароль", http.StatusUnauthorized)
			return
		}

		logRequest("login", r, logrus.Fields{"user_email": user.Email})
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(ResponsePayload{
			Status:  "success",
			Message: "Успешный вход",
		})
	} else if r.Method == http.MethodPut {
		// Registration logic
		var user User
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&user)
		defer r.Body.Close()
		if err != nil || user.Email == "" || user.Password == "" {
			handleError(w, fmt.Errorf("invalid registration data"), "Некорректные данные для регистрации", http.StatusBadRequest)
			return
		}

		var existingUser User
		if err := db.Where("email = ?", user.Email).First(&existingUser).Error; err == nil {
			handleError(w, fmt.Errorf("email already in use"), "Логин занят", http.StatusConflict)
			return
		}

		if err := db.Create(&user).Error; err != nil {
			handleError(w, err, "Ошибка при регистрации пользователя", http.StatusInternalServerError)
			return
		}

		logRequest("register", r, logrus.Fields{"user_email": user.Email})
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(ResponsePayload{
			Status:  "success",
			Message: "Пользователь успешно зарегистрирован",
		})
	} else {
		handleError(w, fmt.Errorf("method not allowed"), "Метод не поддерживается", http.StatusMethodNotAllowed)
	}
}

// Handle CRUD operations for bookings
func handleBookings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Create a booking
		var booking Booking
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&booking)
		defer r.Body.Close()
		if err != nil || booking.Date == "" || booking.Time == "" || booking.Field == "" {
			handleError(w, fmt.Errorf("invalid booking data"), "Некорректные данные бронирования", http.StatusBadRequest)
			return
		}

		if err := db.Create(&booking).Error; err != nil {
			handleError(w, err, "Ошибка при создании бронирования", http.StatusInternalServerError)
			return
		}

		logRequest("create_booking", r, logrus.Fields{"booking_field": booking.Field})
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(ResponsePayload{
			Status:  "success",
			Message: "Бронирование создано",
		})
	} else if r.Method == http.MethodGet {
		// Retrieve bookings
		var bookings []Booking
		if err := db.Find(&bookings).Error; err != nil {
			handleError(w, err, "Ошибка при получении списка бронирований", http.StatusInternalServerError)
			return
		}

		logRequest("list_bookings", r, nil)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(bookings)
	} else if r.Method == http.MethodPut {
		// Update booking
		var booking Booking
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&booking)
		defer r.Body.Close()
		if err != nil || booking.ID == 0 {
			handleError(w, fmt.Errorf("invalid booking ID"), "Некорректные данные бронирования", http.StatusBadRequest)
			return
		}

		var existingBooking Booking
		if err := db.First(&existingBooking, booking.ID).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				handleError(w, err, "Бронирование с указанным ID не найдено", http.StatusNotFound)
				return
			}
			handleError(w, err, "Ошибка при проверке бронирования", http.StatusInternalServerError)
			return
		}

		if err := db.Save(&booking).Error; err != nil {
			handleError(w, err, "Ошибка при обновлении бронирования", http.StatusInternalServerError)
			return
		}

		logRequest("update_booking", r, logrus.Fields{"booking_id": booking.ID})
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(ResponsePayload{
			Status:  "success",
			Message: "Бронирование обновлено",
		})
	} else if r.Method == http.MethodDelete {
		// Delete booking
		var booking Booking
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&booking)
		defer r.Body.Close()
		if err != nil || booking.ID == 0 {
			handleError(w, fmt.Errorf("invalid booking ID"), "Некорректные данные бронирования", http.StatusBadRequest)
			return
		}

		var existingBooking Booking
		if err := db.First(&existingBooking, booking.ID).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				handleError(w, err, "Бронирование с указанным ID не найдено", http.StatusNotFound)
				return
			}
			handleError(w, err, "Ошибка при проверке бронирования", http.StatusInternalServerError)
			return
		}

		if err := db.Delete(&existingBooking).Error; err != nil {
			handleError(w, err, "Ошибка при удалении бронирования", http.StatusInternalServerError)
			return
		}

		logRequest("delete_booking", r, logrus.Fields{"booking_id": booking.ID})
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(ResponsePayload{
			Status:  "success",
			Message: "Бронирование удалено",
		})
	} else {
		handleError(w, fmt.Errorf("method not allowed"), "Метод не поддерживается", http.StatusMethodNotAllowed)
	}
}

// Configure the logger to save logs to a JSON file
func configureLogger() {
	file, err := os.OpenFile("server_logs.json", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		logrus.Fatal("Failed to log to file, using default stderr")
	}
	logger.SetOutput(file)
	logger.SetFormatter(&logrus.JSONFormatter{})
}

// Main function
func main() {
	initDB()
	configureLogger()

	mux := http.NewServeMux()
	mux.HandleFunc("/auth", rateLimited(handleAuth))
	mux.HandleFunc("/bookings", rateLimited(handleBookings))

	logger.Info("Сервер запущен на порту 8080...")
	if err := http.ListenAndServe(":8080", enableCORS(mux)); err != nil {
		logger.WithField("error", err).Fatal("Ошибка запуска сервера")
	}
}
