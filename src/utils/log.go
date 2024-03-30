package utils

import (
    "log"
    "os"
	"time"
	"path/filepath"
)

var (
    ErrorLog *log.Logger
)

func Logger() {
    // Create a log file
	currentDate := time.Now().Format("2006-01-02")

	logDir := "logs"
    if _, err := os.Stat(logDir); os.IsNotExist(err) {
        os.Mkdir(logDir, os.ModePerm)
    }
	logFilePath := filepath.Join(logDir, currentDate+".log")

    logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
    if err != nil {
        log.Fatal("Error creating log file: ", err)
    }

    // Set the logger output to the log file
    ErrorLog = log.New(logFile, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
}
