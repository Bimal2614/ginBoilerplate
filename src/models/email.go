package models

type EmailOtp struct {

	// Primary key ID
	ID uint `gorm:"primaryKey" json:"id"`

	Email string `json:"email"`
	OTP   string `json:"otp"`

	// User model foreign key and on delete cascade
	UserID uint `json:"user_id" gorm:"onDelete:CASCADE" gorm:"foreignKey:UserID"`

	// CreatedAt and UpdatedAt fields
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}
