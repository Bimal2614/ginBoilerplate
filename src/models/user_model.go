package models

import "time"

// Crete a user model with email, password, username, created_at, updated_at, is_active, is_verified, and is_deleted fields

type User struct {
	ID       uint   `gorm:"primaryKey" json:"id"`
	Email    string `gorm:"unique" json:"email"`
	Password string `json:"password"`
	Username string `gorm:"unique" json:"username"`

	CreatedAt time.Time `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt time.Time `json:"updated_at" gorm:"autoUpdateTime"`

	IsActive   bool `json:"is_active" gorm:"default:true"`
	IsVerified bool `json:"is_verified" gorm:"default:false"`
	IsDeleted  bool `json:"is_deleted" gorm:"default:false"`
}
