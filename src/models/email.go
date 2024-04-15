package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type EmailOtp struct {

	// Primary key ID
	ID string `gorm:"primaryKey" json:"id"`

	Email string `json:"email"`
	OTP   uint   `json:"otp"`

	// User model foreign key and on delete cascade
	UserID string `json:"user_id" gorm:"onDelete:CASCADE;foreignKey:UserID"`

	// CreatedAt and UpdatedAt fields
	CreatedAt time.Time `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt time.Time `json:"updated_at" gorm:"autoUpdateTime"`
}

func (user *EmailOtp) BeforeCreate(tx *gorm.DB) (err error) {
	if user.ID == "" {
		user.ID = uuid.NewString()
	}
	return nil
}
