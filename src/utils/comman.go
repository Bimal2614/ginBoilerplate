package utils

import (
	"fmt"
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
