package controllers

import (
	"net/http"
	"regexp"
	"fmt"

	"github.com/gin-gonic/gin"

	"github.com/bimal2614/ginBoilerplate/src/models"

	"github.com/bimal2614/ginBoilerplate/src/crud"

	// "github.com/bimal2614/ginBoilerplate/database"

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
		utils.ErrorLog.Println("Error:", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	//  check is user exists
	dbUser, err := crud.UserExistsByEmail(user.Email)
	if err != nil {
		utils.ErrorLog.Println("Error:", "User not found!", user.Email)
		c.JSON(http.StatusBadRequest, gin.H{"error": "User not found!"})
		return
	}

	// check user verified or not
	if !dbUser.IsVerified{
		utils.ErrorLog.Println("Error:", "User not verified!", user.Email)
		c.JSON(http.StatusBadRequest, gin.H{"error": "User not verified!"})
		return
	}

	// Compare the passwords
	if !utils.ComparePasswords(dbUser.Password, user.Password) {
		utils.ErrorLog.Println("Error:", "Invalid password!", user.Email)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid password"})
		return
	}

	// Generate a JWT token
	refreshtoken, accesstoken, err := utils.GenerateToken(user.ID, user.Email)
	if err != nil {
		utils.ErrorLog.Println("Error:", "Error generating JWT token!", user.Email)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Error generating JWT token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"refreshToken": refreshtoken, "accessToken": accesstoken})
}

func (u *UserController) Register(c *gin.Context) {
	// Get the JSON body and decode into variables
	var user models.User
	if err := c.ShouldBindJSON(&user); err != nil {
		utils.ErrorLog.Println("Error:", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// check for already existing user by email
	_, err := crud.UserExistsByEmail(user.Email)
	if err == nil {
		utils.ErrorLog.Println("Error:", "User already exists!", user.Email)
		c.JSON(http.StatusBadRequest, gin.H{"error": "User already exists!"})
		return
	}

	// check user name unique or not
	if err := crud.CheckUserName(user.Username); err == nil {
		errorMessage := fmt.Sprintf("%s username not available!", user.Username)
		utils.ErrorLog.Println("Error:", errorMessage, user.Email)
		c.JSON(http.StatusBadRequest, gin.H{"error": errorMessage})
		return
	}

	// check for the length of the password and email structure
	if len(user.Password) < 6 {
		utils.ErrorLog.Println("Error:", "Password must be at least 6 characters long!", user.Email)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password must be at least 6 characters long"})
		return
	}

	// RegEx for email validation
	emailRegEx := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegEx.MatchString(user.Email) {
		utils.ErrorLog.Println("Error:", "Invalid email address!", user.Email)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email address"})
		return
	}

	// encrypt the password before creating the user
	passwordHash, err := utils.EncryptPassword(user.Password)
	if err != nil {
		utils.ErrorLog.Println("Error:", "Error encrypting password!", user.Email)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Error encrypting password"})
		return
	}
	user.Password = passwordHash

	if err := crud.CreateUser(&user); err != nil {
		utils.ErrorLog.Println("Error:", "Error creating user!", user.Email)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Error creating user"})
		return
	}

	otp := utils.GenerateOTP()
	// Send the OTP to the user's email
	if err := utils.SendOTP(user.Email, otp); err != nil {
		utils.ErrorLog.Println("Error:", "Error sending OTP!", user.Email)
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
		utils.ErrorLog.Println("Error:", "Error saving OTP!", user.Email)
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

func ReSendOTP(c *gin.Context) {
	// Get the JSON body and decode into variables
	var user schemas.ReSendOTPInput
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// Check if the user exists in the database
	_, err := crud.UserExistsByEmail(user.Email)
	if err != nil {
		utils.ErrorLog.Println("Error:", "User not found!", user.Email)
		c.JSON(http.StatusBadRequest, gin.H{"error": "User not found!"})
		return
	}
	// if err := database.DB.Where("email = ?", user.Email).First(&user).Error; err != nil {
	// 	c.JSON(http.StatusBadRequest, gin.H{"error": "Record not found!"})
	// 	return
	// }

	// Generate an OTP
	otp := utils.GenerateOTP()
	// Send the OTP to the user's email
	if err := utils.SendOTP(user.Email, otp); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Error sending OTP"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "OTP sent successfully"})
}

func (u *UserController) VerifyOTP(c *gin.Context) {
	// Get the JSON body and decode into variables
	var request_data schemas.VerifyOTPInput
	if err := c.ShouldBindJSON(&request_data); err != nil {
		utils.ErrorLog.Println("Error:", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if the user exists in the database
	user, err := crud.UserExistsByEmail(request_data.Email)
	if err != nil {
		utils.ErrorLog.Println("Error:", "Record not found!", request_data.Email)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Record not found!"})
		return
	}

	//  check if the user is already verified
	if user.IsVerified {
		utils.ErrorLog.Println("Error:", "User already verified!", user.Email)
		c.JSON(http.StatusBadRequest, gin.H{"error": "User already verified!"})
		return
	}

	// Check if the OTP exists in the database
	emailOtp, err := crud.VerifyEmailOtp(request_data.Email, request_data.OTP)
	if err != nil {
		utils.ErrorLog.Println("Error:", "OTP not found!", request_data.Email)
		c.JSON(http.StatusBadRequest, gin.H{"error": "OTP not found!"})
		return
	}

	// change the status of the user to verified
	user.IsVerified = true
	if err := crud.UpdateUser(user); err != nil {
		utils.ErrorLog.Println("Error:", "Error updating user!", user.Email)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Error updating user"})
		return
	}

	// Delete the OTP from the database
	if err := crud.DeleteEmailOtp(emailOtp); err != nil {
		utils.ErrorLog.Println("Error:", "Error deleting OTP!", user.Email)
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
