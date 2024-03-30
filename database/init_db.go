package database

import (
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"os"
	"fmt"
	// import user model
	"github.com/bimal2614/ginBoilerplate/src/models"
)

var DB *gorm.DB // Exported package-level variable

// InitDB initializes the database connection
func InitDB() error {
	var err error
	host := os.Getenv("POSTGRES_HOST")
    username := os.Getenv("POSTGRES_USER")
    password := os.Getenv("POSTGRES_PASSWORD")
    dbname := os.Getenv("POSTGRES_DATABASE")
    port := os.Getenv("POSTGRES_PORT")

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable", host, username, password, dbname, port)
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return err
	}

	// Migrate the schema
	DB.AutoMigrate(&models.User{})
	DB.AutoMigrate(&models.EmailOtp{})
	return nil
}
