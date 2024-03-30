package controllers

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bimal2614/ginBoilerplate/src/utils"
	"github.com/gin-gonic/gin"
)

type CronjobController struct {
	LogDirectory string
	MaxAgeInDays int
}

func NewCronjobController(logDirectory string, maxAgeInDays int) *CronjobController {
	return &CronjobController{
		LogDirectory: logDirectory,
		MaxAgeInDays: maxAgeInDays,
	}
}

func (cont *CronjobController) DeleteOldLogFiles(c *gin.Context) {
	files, err := os.ReadDir(cont.LogDirectory)
	if err != nil {
		utils.ErrorLog.Println("Failed to read log directory:", err)
		c.JSON(500, gin.H{"error": "Failed to read log directory"})
		return
	}

	currentDate := time.Now()
	var deletedFiles []string

	for _, file := range files {
		fileName := file.Name()
		if !strings.HasSuffix(fileName, ".log") {
			continue
		}

		dateStr := strings.TrimSuffix(fileName, ".log")
		fileDate, err := time.Parse("2006-01-02", dateStr)
		if err != nil {
			utils.ErrorLog.Printf("Failed to parse date from file name %s: %v\n", fileName, err)
			continue
		}

		if currentDate.Sub(fileDate).Hours()/24 > float64(cont.MaxAgeInDays) {
			err := os.Remove(fmt.Sprintf("%s/%s", cont.LogDirectory, fileName))
			if err != nil {
				utils.ErrorLog.Printf("Failed to delete file %s: %v\n", fileName, err)
				continue
			}
			deletedFiles = append(deletedFiles, fileName)
		}
	}

	if len(deletedFiles) == 0 {
		c.JSON(200, gin.H{"message": "No old log files to delete"})
	} else {
		c.JSON(200, gin.H{"message": "Old log files deleted successfully", "deletedFiles": deletedFiles})
	}
}
