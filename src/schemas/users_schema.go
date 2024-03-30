package schemas

type UserRegisterOutput struct {
	ID       uint   `json:"id"`
	Email    string `json:"email"`
	Username string `json:"username"`
}

type VerifyOTPInput struct {
	Email string `json:"email" binding:"required"`
	OTP   string `json:"otp" binding:"required"`
}

type ReSendOTPInput struct {
	Email string `json:"email" binding:"required"`
}

type ForgotPasswordInput struct {
	Password string `json:"password" binding:"required"`
	Email string `json:"email" binding:"required"`
	OTP   string `json:"otp" binding:"required"`
}