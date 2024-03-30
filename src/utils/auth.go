package utils

import (
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

// EncryptPassword encrypts a password
func EncryptPassword(password string) (string, error) {
	// Encrypt the password
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Println("Error encrypting password")
		return "", err
	}

	return string(hash), nil
}

// ComparePasswords compares a hashed password with a plaintext password
func ComparePasswords(hashedPassword, password string) bool {
	// Compare the passwords

	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		fmt.Println("Error comparing passwords")
		return false
	}

	return true
}

// GenerateToken generates a JWT token
func GenerateToken(userID uint, Email string) (string, string, error) {
	// Create a new token object with ID and password
	// The refresh token and Access token
	// refresh token validation time 7 days
	// access token validation time  3 hours

	refreshTokenString := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userID": userID,
		"Email":  Email,
		"exp":    168 * 60 * 60,
	})

	accessTokenString := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userID": userID,
		"Email":  Email,
		"exp":    3 * 60 * 60,
	})

	// Sign the token with the secret
	refreshToken, err := refreshTokenString.SignedString([]byte(os.Getenv("SECRET")))
	if err != nil {
		fmt.Println("Error signing refresh token")
		return "", "", err
	}

	accessToken, err := accessTokenString.SignedString([]byte(os.Getenv("SECRET")))
	if err != nil {
		fmt.Println("Error signing access token")
		return "", "", err
	}

	return refreshToken, accessToken, nil
}

// ParseToken parses a JWT token
func ParseToken(tokenString string) (jwt.MapClaims, error) {
	// Parse the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("SECRET")), nil
	})
	if err != nil {
		fmt.Println("Error parsing JWT token")
		return nil, err
	}

	// Extract the claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		fmt.Println("Error extracting claims")
		return nil, err
	}

	return claims, nil
}

// ExtractToken extracts the token from the Authorization header
func ExtractToken(authorizationHeader string) string {
	// Extract the token
	return authorizationHeader
}

// VerifyToken verifies a JWT token
func VerifyToken(tokenString string) (bool, error) {
	// Parse the token
	claims, err := ParseToken(tokenString)
	if err != nil {
		fmt.Println("Error parsing JWT token")
		return false, err
	}

	// Validate the token
	_, ok := claims["userID"]
	if !ok {
		fmt.Println("Error validating JWT token")
		return false, err
	}

	return true, nil
}

// func EncryptPassword
// GenerateToken

func GenerateOTP() string {

	rand.Seed(time.Now().UnixNano())
	min := 100000
	max := 999999
	return fmt.Sprintf("%v", rand.Intn(max-min+1)+min)
}

func SendOTP(email, otp string) error {
	// Send the OTP to the user's email
	fmt.Println("OTP: ", otp)
	return nil
}

func NormalizeEmail(email string) string {
	// Normalize the email, convert to lowercase
	return strings.ToLower(email)
}
