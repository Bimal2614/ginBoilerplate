package models

// Crete a user model with email, password, username, created_at, updated_at, is_active, is_verified, and is_deleted fields

type User struct {
	ID       uint   `gorm:"primaryKey" json:"id"`
	Email    string `gorm:"unique" json:"email"`
	Password string `json:"password"`
	Username string `gorm:"unique" json:"username"`

	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`

	IsActive   bool `json:"is_active"`
	IsVerified bool `json:"is_verified"`
	IsDeleted  bool `json:"is_deleted"`
}
