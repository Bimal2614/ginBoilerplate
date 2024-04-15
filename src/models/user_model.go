package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Crete a user model with email, password, username, created_at, updated_at, is_active, is_verified, and is_deleted fields

type User struct {
	ID         string `gorm:"primaryKey" json:"id"`
	Email      string `gorm:"unique" json:"email"`
	Password   string `json:"password"`
	Username   string `gorm:"unique" json:"username"`
	SecretKey  string `json:"secret_key"`
	RecoverKey string `json:"recover_key"`
	Auth2FA    bool   `json:"auth2_fa" gorm:"default:false"`
	Verifier   string `json:"verifier"`
	Provider   string `json:"provider"`
	Image      string `json:"image"`

	CreatedAt time.Time `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt time.Time `json:"updated_at" gorm:"autoUpdateTime"`

	IsActive   bool `json:"is_active" gorm:"default:true"`
	IsVerified bool `json:"is_verified" gorm:"default:false"`
	IsDeleted  bool `json:"is_deleted" gorm:"default:false"`
}

func (user *User) BeforeCreate(tx *gorm.DB) (err error) {
	if user.ID == "" {
		user.ID = uuid.NewString()
	}
	return nil
}
