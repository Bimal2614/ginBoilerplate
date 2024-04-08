package utils

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/bimal2614/ginBoilerplate/src/crud"
	"github.com/bimal2614/ginBoilerplate/src/models"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

// Secret key
var secretKey = []byte(os.Getenv("SECRET_KEY"))

// EncryptPassword encrypts a password
func EncryptPassword(password string) (string, error) {
	// Combine password and secret key
	passwordWithPepper := append([]byte(password), secretKey...)

	// Encrypt the password
	hash, err := bcrypt.GenerateFromPassword(passwordWithPepper, bcrypt.DefaultCost)
	if err != nil {
		fmt.Println("Error encrypting password")
		return "", err
	}

	return string(hash), nil
}

// ComparePasswords compares a hashed password with a plaintext password
func ComparePasswords(hashedPassword, password string) bool {
	// Compare the passwords
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password+string(secretKey)))
	if err != nil {
		fmt.Println("Error comparing passwords")
		return false
	}

	return true
}

// GenerateToken generates a JWT token
func GenerateToken(userID string, Email string, Verifier string) (string, string, error) {
	// Create a new token object with ID and Email
	// The refresh token and Access token
	// refresh token validation time 7 days
	// access token validation time  24 hours

	refreshTokenString := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userID":   userID,
		"Email":    Email,
		"Verifier": Verifier,
		"exp":      time.Now().Add(7 * 24 * time.Hour).Unix(),
	})

	accessTokenString := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userID":   userID,
		"Email":    Email,
		"Verifier": Verifier,
		"exp":      time.Now().Add(24 * time.Hour).Unix(),
	})

	// Sign the token with the secret
	refreshToken, err := refreshTokenString.SignedString(secretKey)
	if err != nil {
		fmt.Println("Error signing refresh token")
		return "", "", err
	}

	accessToken, err := accessTokenString.SignedString(secretKey)
	if err != nil {
		fmt.Println("Error signing access token")
		return "", "", err
	}

	return refreshToken, accessToken, nil
}

func CreateEmailAccessToken(email string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": email,
		"exp":   time.Now().Add(time.Minute * 10).Unix(),
	})
	signedToken, _ := token.SignedString([]byte(os.Getenv("ENCRYPTION_KEY")))
	return signedToken
}

func GetCurrentUser(tokenString string) (*models.User, error) {
	if tokenString == "" {
		return nil, fmt.Errorf("authorization header missing")
	}

	parts := strings.Split(tokenString, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return nil, fmt.Errorf("invalid token format")
	}
	tokenString = parts[1]

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	id, ok := claims["userID"].(string)
	if !ok {
		return nil, fmt.Errorf("Could not validate credentials")
	}

	Key, ok := claims["Verifier"].(string)
	if !ok {
		return nil, fmt.Errorf("Could not validate credentials")
	}
	user, err := crud.GetUser(id)
	if err != nil || user.IsDeleted || Key != user.Verifier || !user.IsVerified {
		return nil, fmt.Errorf("Could not validate credentials")
	}

	return user, nil
}

func DecodeEmailAccessToken(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("ENCRYPTION_KEY")), nil
	})
	if err != nil {
		return "", fmt.Errorf("Could not validate credentials")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return "", fmt.Errorf("Could not validate credentials")
	}
	email := claims["email"].(string)
	return email, nil
}

// ExtractToken extracts the token from the Authorization header
func ExtractToken(authorizationHeader string) string {
	// Extract the token
	return authorizationHeader
}

func GenerateOTP() int {

	// rand.Seed(time.Now().UnixNano())
	min := 100000
	max := 999999
	return rand.Intn(max-min+1) + min
}

// func SendOTP(email, otp string) error {
// 	// Send the OTP to the user's email
// 	fmt.Println("OTP: ", otp)
// 	utils.SendEmail("dummy3154@gmail.com", otp, "hellobbbhbjhbv")
// 	return nil
// }

func NormalizeEmail(email string) string {
	// Normalize the email, convert to lowercase
	return strings.ToLower(email)
}

func GenerateRandomKey(length int) string {
	key := make([]byte, length)
	_, err := rand.Read(key)
	if err != nil {
		return "testing-mode"
	}
	return hex.EncodeToString(key)
}
