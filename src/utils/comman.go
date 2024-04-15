package utils

import (
	"encoding/json"
	"fmt"
	"log"
	"mime/multipart"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
)

func SaveStaticFile(c *gin.Context, file *multipart.FileHeader, userID string) string {
	filePath := fmt.Sprintf("static/%s/%s", userID, strings.ReplaceAll(file.Filename, " ", "_"))

	if err := os.MkdirAll(filepath.Dir(filePath), os.ModePerm); err != nil {
		return ""
	}

	if err := c.SaveUploadedFile(file, filePath); err != nil {
		return ""
	}

	return filePath
}

func CreateGoogleCredFile() {
	file, err := os.Create("google_service.json")
	if err != nil {
		log.Fatalf("Error creating google auth file: %v", err)
	}
	defer file.Close()

	// Initialize a map with key-value pairs.
	data := map[string]string{
		"type":                        os.Getenv("GOOGLE_TYPE"),
		"project_id":                  os.Getenv("GOOGLE_PROJECT_ID"),
		"private_key_id":              os.Getenv("GOOGLE_PRIVATE_KEY_ID"),
		"private_key":                 os.Getenv("GOOGLE_PRIVATE_KEY"),
		"client_email":                os.Getenv("GOOGLE_CLIENT_EMAIL"),
		"client_id":                   os.Getenv("GOOGLE_CLIENT_ID"),
		"auth_uri":                    os.Getenv("GOOGLE_AUTH_URI"),
		"token_uri":                   os.Getenv("GOOGLE_TOKEN_URI"),
		"auth_provider_x509_cert_url": os.Getenv("GOOGLE_AUTH_PROVIDER_X509_CERT_URL"),
		"client_x509_cert_url":        os.Getenv("GOOGLE_CLIENT_X509_CERT_URL"),
		"universe_domain":             os.Getenv("GOOGLE_UNIVERSE_DOMAIN"),
	}

	// Marshal the map into JSON format.
	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Fatalf("Error marshalling google auth JSON: %v", err)
	}
	// Write the JSON data to the file.
	if _, err := file.Write(jsonData); err != nil {
		log.Fatalf("Error writing JSON to google auth file: %v", err)
	}
}
