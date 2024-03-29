package crud

import (
	"github.com/bimal2614/ginBoilerplate/database"
	"github.com/bimal2614/ginBoilerplate/src/models"
)

// CreateEmailOtp creates a new email otp record in the database
func CreateEmailOtp(emailOtp *models.EmailOtp) error {
	if err := database.DB.Create(emailOtp).Error; err != nil {
		return err
	}
	return nil
}

func DeleteEmailOtp(emailOtp *models.EmailOtp) error {
	if err := database.DB.Delete(emailOtp).Error; err != nil {
		return err
	}
	return nil
}
