package controllers

import (
	"net/http"
	"regexp"

	"github.com/gin-gonic/gin"

	"github.com/bimal2614/ginBoilerplate/src/models"

	"github.com/bimal2614/ginBoilerplate/src/crud"

	"github.com/bimal2614/ginBoilerplate/database"

	"github.com/bimal2614/ginBoilerplate/src/schemas"

	"github.com/bimal2614/ginBoilerplate/src/utils"
)

type UserController struct {
}

func NewUserController() *UserController {
	return &UserController{}
}

// Login function
func (u *UserController) Login(c *gin.Context) {

	// Get the JSON body and decode into variables
	var user models.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var dbUser models.User
	//  check is user exists
	if err := database.DB.Where("email = ?", user.Email).First(&dbUser).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User not found!"})
		return
	}

	// Compare the passwords
	if !utils.ComparePasswords(dbUser.Password, user.Password) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid password"})
		return
	}

	// Generate a JWT token
	refreshtoken, accesstoken, err := utils.GenerateToken(user.ID, user.Email)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Error generating JWT token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"refreshToken": refreshtoken, "accessToken": accesstoken})
}

func (u *UserController) Register(c *gin.Context) {
	// Get the JSON body and decode into variables
	var user models.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// check for already existing user by email

	if err := database.DB.Where("email = ?", user.Email).First(&user).Error; err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User already exists!"})
		return
	}

	// check for the length of the password and email structure
	if len(user.Password) < 6 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password must be at least 6 characters long"})
		return
	}

	// RegEx for email validation

	emailRegEx := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegEx.MatchString(user.Email) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email address"})
		return
	}

	// encrypt the password before creating the user
	user.Password = utils.EncryptPassword(user.Password)

	if err := crud.CreateUser(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Error creating user"})
		return
	}

	otp := utils.GenerateOTP()
	// Send the OTP to the user's email
	if err := utils.SendOTP(user.Email, otp); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Error sending OTP"})
		return
	}

	// save the otp in the database
	emailOtp := models.EmailOtp{
		Email:  user.Email,
		OTP:    otp,
		UserID: user.ID,
	}
	if err := crud.CreateEmailOtp(&emailOtp); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Error saving OTP"})
		return
	}

	//  prepare the response with user schema
	userSchema := schemas.UserRegisterOutput{
		ID:       user.ID,
		Email:    user.Email,
		Username: user.Username,
	}
	c.JSON(http.StatusOK, gin.H{"data": userSchema})
}

// func sendOTP(c *gin.Context) {
// 	// Get the JSON body and decode into variables
// 	var user models.User
// 	if err := c.ShouldBindJSON(&user); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
// 		return
// 	}
// 	// Check if the user exists in the database
// 	if err := database.DB.Where("email = ?", user.Email).First(&user).Error; err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Record not found!"})
// 		return
// 	}
// 	// Generate an OTP
// 	otp := auth.GenerateOTP()
// 	// Send the OTP to the user's email
// 	if err := auth.SendOTP(user.Email, otp); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Error sending OTP"})
// 		return
// 	}
// 	c.JSON(http.StatusOK, gin.H{"message": "OTP sent successfully"})
// }

func (u *UserController) VerifyOTP(c *gin.Context) {
	// Get the JSON body and decode into variables
	var request_data schemas.VerifyOTPInput
	if err := c.ShouldBindJSON(&request_data); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user models.User
	// Check if the user exists in the database
	if err := database.DB.Where("email = ?", request_data.Email).First(&user).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Record not found!"})
		return
	}

	//  check if the user is already verified
	if user.IsVerified {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User already verified!"})
		return
	}

	// Check if the OTP exists in the database
	var emailOtp models.EmailOtp
	if err := database.DB.Where("email = ? AND otp = ?", request_data.Email, request_data.OTP).First(&emailOtp).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "OTP not found!"})
		return
	}

	// change the status of the user to verified
	user.IsVerified = true
	if err := crud.UpdateUser(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Error updating user"})
		return
	}

	// Delete the OTP from the database
	if err := crud.DeleteEmailOtp(&emailOtp); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Error deleting OTP"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "OTP verified successfully"})
}

// func forgotPassword(c *gin.Context) {
// 	// Get the JSON body and decode into variables
// 	var user models.User
// 	if err := c.ShouldBindJSON(&user); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
// 		return
// 	}
// 	// Check if the user exists in the database
// 	if err := database.DB.Where("email = ?", user.Email).First(&user).Error; err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Record not found!"})
// 		return
// 	}
// 	// Generate a new password
// 	newPassword := auth.GeneratePassword()
// 	// Update the user's password
// 	user.Password = newPassword
// 	if err := crud.UpdateUser(&user); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Error updating password"})
// 		return
// 	}
// 	// Send the new password to the user's email
// 	if err := auth.SendPassword(user.Email, newPassword); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Error sending password"})
// 		return
// 	}
// 	c.JSON(http.StatusOK, gin.H{"message": "Password reset successfully"})
// }

// func resetPassword(c *gin.Context) {
// 	// Get the JSON body and decode into variables
// 	var user models.User
// 	if err := c.ShouldBindJSON(&user); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
// 		return
// 	}
// 	// Check if the user exists in the database
// 	if err := database.DB.Where("email = ?", user.Email).First(&user).Error; err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Record not found!"})
// 		return
// 	}
// 	// Update the user's password
// 	if err := crud.UpdateUser(&user); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Error updating password"})
// 		return
// 	}
// 	c.JSON(http.StatusOK, gin.H{"message": "Password reset successfully"})
// }

// func getUsers(c *gin.Context) {
// 	users, err := crud.GetUsers()
// 	if err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Error fetching users"})
// 		return
// 	}
// 	c.JSON(http.StatusOK, gin.H{"data": users})
// }

// func getUser(c *gin.Context) {
// 	id := c.Param("id")
// 	user, err := crud.GetUser(id)
// 	if err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Error fetching user"})
// 		return
// 	}
// 	c.JSON(http.StatusOK, gin.H{"data": user})
// }
