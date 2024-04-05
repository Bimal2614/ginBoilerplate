package schemas

import (
	"time"
)

type UserRegisterOutput struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Username string `json:"username"`
}

type VerifyOTPInput struct {
	Email string `json:"email" binding:"required"`
	OTP   uint   `json:"otp" binding:"required"`
}

type ReSendOTPInput struct {
	Email string `json:"email" binding:"required"`
}

type ForgotPasswordInput struct {
	NewPassword string `json:"newpassword" binding:"required"`
	Email       string `json:"email" binding:"required"`
	OTP         uint   `json:"otp" binding:"required"`
}

type ChangePasswordInput struct {
	OldPassword string `json:"oldpassword" binding:"required"`
	NewPassword string `json:"newpassword" binding:"required"`
}

type GoogleLoginInput struct {
	IDToken string `json:"email" binding:"required"`
}

type UserResponse struct {
	ID         string    `json:"id"`
	Email      string    `json:"email"`
	Username   string    `json:"username"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	IsActive   bool      `json:"is_active"`
	IsVerified bool      `json:"is_verified"`
	Auth2FA    bool      `json:"auth_2fa"`
	IsDeleted  bool      `json:"is_deleted"`
}

type AuthVerifyInput struct {
	UserID     string `json:"user_id"`
	SecretKey  string `json:"secret_key"`
	RecoverKey string `json:"recover_key"`
	Auth2FA    bool   `json:"auth2_fa"`
	InsideFlag bool   `json:"inside_flage"`
	Enable2FA  bool   `json:"enable_2fa"`
	OTP        string `json:"otp"`
}
