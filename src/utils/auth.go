package utils

import (
	"fmt"
	"os"

	"github.com/dgrijalva/jwt-go"
)

// GenerateToken generates a JWT token
func GenerateToken(userID uint) (string, error) {
	// Create a new token object
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userID": userID,
	})

	// Sign the token with the secret
	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))
	if err != nil {
		fmt.Println("Error generating JWT token")
		return "", err
	}

	return tokenString, nil
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
