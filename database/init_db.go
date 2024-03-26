package database

import (
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	// import user model
	"github.com/bimal2614/ginBoilerplate/src/models"
)

var DB *gorm.DB // Exported package-level variable

// InitDB initializes the database connection
func InitDB() error {
	var err error
	dsn := "host=localhost user=yourusername password=yourpassword dbname=yourdbname port=5432 sslmode=disable"
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return err
	}
	// Migrate the schema
	DB.AutoMigrate(&models.User{})
	return nil
}
