package utils

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

var (
	ErrorLog *log.Logger
)

func Logger() {

	currentDate := time.Now().Format("2006-01-02")
	logDir := getLogDir()
	ensureDirExists(logDir)
	logFilePath := filepath.Join(logDir, fmt.Sprintf("%s.log", currentDate))

	logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Error opening or creating log file: %v", err)
	}

	ErrorLog = log.New(logFile, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
}

func getLogDir() string {
	logDir := os.Getenv("LOG_DIR")
	if logDir == "" {
		logDir = "logs"
	}
	return logDir
}

func ensureDirExists(dirName string) {
	if _, err := os.Stat(dirName); os.IsNotExist(err) {
		if err := os.MkdirAll(dirName, os.ModePerm); err != nil {
			log.Fatalf("Error creating directory %s: %v", dirName, err)
		}
	}
}
