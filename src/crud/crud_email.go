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


func VerifyEmailOtp(email string, otp string) (*models.EmailOtp, error) {
	var emailOtp models.EmailOtp
	if err := database.DB.Where("email = ? AND otp = ?", email, otp).First(&emailOtp).Error; err != nil {
		return nil, err
	}
	
	return &emailOtp, nil
}
