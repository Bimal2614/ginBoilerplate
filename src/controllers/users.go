package controllers

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image/png"
	"net/http"
	"regexp"
	"time"

	"github.com/bimal2614/ginBoilerplate/src/crud"
	"github.com/bimal2614/ginBoilerplate/src/models"
	"github.com/bimal2614/ginBoilerplate/src/schemas"
	"github.com/bimal2614/ginBoilerplate/src/utils"
	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
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
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	user.Email = utils.NormalizeEmail(user.Email)
	//  check is user exists
	dbUser, err := crud.UserExistsByEmail(user.Email)
	if err != nil {
		utils.ErrorLog.Println("Error:", "User not found!", user.Email)
		c.JSON(http.StatusNotFound, gin.H{"message": "User not found!"})
		return
	}

	// check user verified or not
	if !dbUser.IsVerified {
		c.JSON(http.StatusOK, gin.H{"id": dbUser.ID, "email": dbUser.Email, "is_verified": dbUser.IsVerified})
		return
	}

	// Compare the passwords
	if !utils.ComparePasswords(dbUser.Password, user.Password) {
		utils.ErrorLog.Println("Error:", "Invalid password!", user.Email)
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid password"})
		return
	}

	if dbUser.Auth2FA {
		c.JSON(http.StatusOK, gin.H{
			"message": "Please otp verify",
			"data": gin.H{
				"id":          dbUser.ID,
				"email":       dbUser.Email,
				"is_verified": dbUser.IsVerified,
				"auth_2fa":    dbUser.Auth2FA,
			},
		})
		return
	}
	// Generate a JWT token
	refreshtoken, accesstoken, err := utils.GenerateToken(dbUser.ID, user.Email)
	if err != nil {
		utils.ErrorLog.Println("Error:", "Error generating JWT token!", user.Email)
		c.JSON(http.StatusBadRequest, gin.H{"message": "Error generating JWT token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":          dbUser.ID,
		"email":       dbUser.Email,
		"is_verified": dbUser.IsVerified,
		"auth_2fa":    dbUser.Auth2FA,
		"token": gin.H{
			"refreshToken": refreshtoken,
			"accessToken":  accesstoken,
		},
	})
}

func (u *UserController) Register(c *gin.Context) {
	// Get the JSON body and decode into variables
	var user models.User
	if err := c.ShouldBindJSON(&user); err != nil {
		utils.ErrorLog.Println("Error:", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	// normalize the email
	user.Email = utils.NormalizeEmail(user.Email)

	// check for already existing user by email
	_, err := crud.UserExistsByEmail(user.Email)
	if err == nil {
		utils.ErrorLog.Println("Error:", "User already exists!", user.Email)
		c.JSON(http.StatusBadRequest, gin.H{"message": "User already exists!"})
		return
	}

	// check user name unique or not
	if err := crud.CheckUserName(user.Username); err == nil {
		errorMessage := fmt.Sprintf("%s username not available!", user.Username)
		utils.ErrorLog.Println("Error:", errorMessage, user.Email)
		c.JSON(http.StatusBadRequest, gin.H{"message": errorMessage})
		return
	}

	// check for the length of the password and email structure
	if len(user.Password) < 6 {
		utils.ErrorLog.Println("Error:", "Password must be at least 6 characters long!", user.Email)
		c.JSON(http.StatusBadRequest, gin.H{"message": "Password must be at least 6 characters long"})
		return
	}

	// RegEx for email validation
	emailRegEx := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegEx.MatchString(user.Email) {
		utils.ErrorLog.Println("Error:", "Invalid email address!", user.Email)
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid email address"})
		return
	}

	// encrypt the password before creating the user
	passwordHash, err := utils.EncryptPassword(user.Password)
	if err != nil {
		utils.ErrorLog.Println("Error:", "Error encrypting password!", user.Email)
		c.JSON(http.StatusBadRequest, gin.H{"message": "Error encrypting password"})
		return
	}
	user.Password = passwordHash

	if err := crud.CreateUser(&user); err != nil {
		utils.ErrorLog.Println("Error:", "Error creating user!", user.Email)
		c.JSON(http.StatusBadRequest, gin.H{"message": "Error creating user"})
		return
	}

	otp := utils.GenerateOTP()
	// Send the OTP to the user's email
	if err := utils.SendOTP(user.Email, otp); err != nil {
		utils.ErrorLog.Println("Error:", "Error sending OTP!", user.Email)
		c.JSON(http.StatusBadRequest, gin.H{"message": "Error sending OTP"})
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
		c.JSON(http.StatusBadRequest, gin.H{"message": "Error saving OTP"})
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

func (u *UserController) ReSendOTP(c *gin.Context) {
	// Get the JSON body and decode into variables
	var user schemas.ReSendOTPInput
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}
	// Check if the user exists in the database
	userDb, err := crud.UserExistsByEmail(user.Email)
	if err != nil {
		utils.ErrorLog.Println("Error:", "User not found!", user.Email)
		c.JSON(http.StatusNotFound, gin.H{"message": "User not found!"})
		return
	}

	// Generate an OTP
	otp := utils.GenerateOTP()
	// Send the OTP to the user's email
	if err := utils.SendOTP(user.Email, otp); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Error sending OTP"})
		return
	}

	emailOtp, _ := crud.OtpExistsByEmail(userDb.Email)
	if emailOtp != nil {
		// If OTP exists, update it
		if err := crud.DeleteEmailOtp(emailOtp); err != nil {
			utils.ErrorLog.Println("Error:", "Error updating OTP!", user.Email)
			c.JSON(http.StatusBadRequest, gin.H{"message": "Error updating OTP"})
			return
		}
	}
	// If OTP doesn't exist, create a new one
	newEmailOtp := models.EmailOtp{
		Email:  userDb.Email,
		OTP:    otp,
		UserID: userDb.ID,
	}

	if err := crud.CreateEmailOtp(&newEmailOtp); err != nil {
		utils.ErrorLog.Println("Error:", "Error creating OTP!", user.Email)
		c.JSON(http.StatusBadRequest, gin.H{"message": "Error creating OTP"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "OTP sent successfully"})
}

func (u *UserController) VerifyOTP(c *gin.Context) {
	// Get the JSON body and decode into variables
	var request_data schemas.VerifyOTPInput
	if err := c.ShouldBindJSON(&request_data); err != nil {
		utils.ErrorLog.Println("Error:", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	// Check if the user exists in the database
	user, err := crud.UserExistsByEmail(request_data.Email)
	if err != nil {
		utils.ErrorLog.Println("Error:", "Record not found!", request_data.Email)
		c.JSON(http.StatusNotFound, gin.H{"message": "Record not found!"})
		return
	}

	//  check if the user is already verified
	if user.IsVerified {
		utils.ErrorLog.Println("Error:", "User already verified!", user.Email)
		c.JSON(http.StatusBadRequest, gin.H{"message": "User already verified!"})
		return
	}

	// Check if the OTP exists in the database
	emailOtp, err := crud.VerifyEmailOtp(request_data.Email, request_data.OTP)
	if err != nil {
		utils.ErrorLog.Println("Error:", "OTP not found!", request_data.Email)
		c.JSON(http.StatusNotFound, gin.H{"message": "OTP not found!"})
		return
	}

	// change the status of the user to verified
	user.IsVerified = true
	if err := crud.UpdateUser(user); err != nil {
		utils.ErrorLog.Println("Error:", "Error updating user!", user.Email)
		c.JSON(http.StatusBadRequest, gin.H{"message": "Error updating user"})
		return
	}

	// Delete the OTP from the database
	if err := crud.DeleteEmailOtp(emailOtp); err != nil {
		utils.ErrorLog.Println("Error:", "Error deleting OTP!", user.Email)
		c.JSON(http.StatusBadRequest, gin.H{"message": "Error deleting OTP"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "OTP verified successfully"})
}

func (u *UserController) ForgotPassword(c *gin.Context) {
	// Get the JSON body and decode into variables
	var user schemas.ForgotPasswordInput
	if err := c.ShouldBindJSON(&user); err != nil {
		utils.ErrorLog.Println("Error:", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	//  check is user exists
	userDb, err := crud.UserExistsByEmail(user.Email)
	if err != nil {
		utils.ErrorLog.Println("Error:", "User not found!", user.Email)
		c.JSON(http.StatusNotFound, gin.H{"message": "User not found!"})
		return
	}

	//  check is otp exists
	emailOtp, _ := crud.OtpExistsByEmail(user.Email)
	if emailOtp != nil {
		//check is otp right or wrong
		if emailOtp.OTP != user.OTP {
			utils.ErrorLog.Println("Error:", "OTP mismatched, Please provide correct OTP!", user.Email)
			c.JSON(http.StatusBadRequest, gin.H{"message": "OTP mismatched, Please provide correct OTP"})
			return
		}
		validityPeriod := 5 * time.Minute
		currentTime := time.Now()
		//check otp time
		if !emailOtp.CreatedAt.Add(validityPeriod).Before(currentTime) {
			// check for the length of the password and email structure
			if len(user.Password) < 6 {
				utils.ErrorLog.Println("Error:", "Password must be at least 6 characters long!", user.Email)
				c.JSON(http.StatusBadRequest, gin.H{"message": "Password must be at least 6 characters long"})
				return
			}
			// Generate a new password
			passwordHash, err := utils.EncryptPassword(user.Password)
			if err != nil {
				utils.ErrorLog.Println("Error:", "Error encrypting password!", user.Email)
				c.JSON(http.StatusBadRequest, gin.H{"message": "Error encrypting password"})
				return
			}
			// Update the user's password
			userDb.Password = passwordHash
			if err := crud.UpdateUser(userDb); err != nil {
				utils.ErrorLog.Println("Error:", "Error updating password!", user.Email)
				c.JSON(http.StatusBadRequest, gin.H{"message": "Error updating password"})
				return
			}

			// Delete the OTP from the database
			if err := crud.DeleteEmailOtp(emailOtp); err != nil {
				utils.ErrorLog.Println("Error:", "Error deleting OTP!", user.Email)
				c.JSON(http.StatusBadRequest, gin.H{"message": "Error deleting OTP"})
				return
			}
		} else {
			// OTP has expired
			utils.ErrorLog.Println("Error:", "OTP has expired!", user.Email)
			c.JSON(http.StatusBadRequest, gin.H{"message": "OTP has expired!"})
			return
		}
	} else {
		// User OTP not add in database
		utils.ErrorLog.Println("Error:", "OTP not found!", user.Email)
		c.JSON(http.StatusNotFound, gin.H{"message": "OTP not found!"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password reset successfully"})
}

func (u *UserController) ChangePassword(c *gin.Context) {
	//Get the JSON body and decode into variables
	var user schemas.ChangePasswordInput
	if err := c.ShouldBindJSON(&user); err != nil {
		utils.ErrorLog.Println("Error:", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	//  check is user exists
	dbUser, err := crud.UserExistsByEmail(user.Email)
	if err != nil {
		utils.ErrorLog.Println("Error:", "User not found!", user.Email)
		c.JSON(http.StatusNotFound, gin.H{"message": "User not found!"})
		return
	}

	// check user verified or not
	if !dbUser.IsVerified {
		utils.ErrorLog.Println("Error:", "User not verified!", user.Email)
		c.JSON(http.StatusBadRequest, gin.H{"message": "User not verified!"})
		return
	}

	//ckeck add user old password and new password
	if user.OldPassword == user.NewPassword {
		utils.ErrorLog.Println("Error:", "Old password and new password are the same!", user.Email)
		c.JSON(http.StatusBadRequest, gin.H{"message": "Old password and new password are the same!"})
		return
	}

	//check old password in db
	comp := utils.ComparePasswords(dbUser.Password, user.OldPassword)
	if !comp {
		utils.ErrorLog.Println("Error:", "Old password is incorrect!", user.Email)
		c.JSON(http.StatusBadRequest, gin.H{"message": "Old password is incorrect"})
		return
	}

	// check for the length of the password
	if len(user.NewPassword) < 6 {
		utils.ErrorLog.Println("Error:", "Password must be at least 6 characters long!", user.Email)
		c.JSON(http.StatusBadRequest, gin.H{"message": "Password must be at least 6 characters long"})
		return
	}

	// encrypt the new password
	passwordHash, err := utils.EncryptPassword(user.NewPassword)
	if err != nil {
		utils.ErrorLog.Println("Error:", "encrypting password!", user.Email)
		c.JSON(http.StatusBadRequest, gin.H{"message": "Error encrypting password"})
		return
	}
	// Update the user's password
	dbUser.Password = passwordHash
	if err := crud.UpdateUser(dbUser); err != nil {
		utils.ErrorLog.Println("Error:", "updating password!", user.Email)
		c.JSON(http.StatusBadRequest, gin.H{"message": "Error updating password"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Password change successfully"})
}

func (u *UserController) GetUsers(c *gin.Context) {
	users, err := crud.GetUsers()
	if err != nil {
		utils.ErrorLog.Println("Error:", "Error fetching users!")
		c.JSON(http.StatusBadRequest, gin.H{"message": "Error fetching users"})
		return
	}

	var userResponses []schemas.UserResponse
	for _, user := range *users {
		userResponses = append(userResponses, schemas.UserResponse{
			ID:         user.ID,
			Email:      user.Email,
			Username:   user.Username,
			CreatedAt:  user.CreatedAt,
			UpdatedAt:  user.UpdatedAt,
			IsActive:   user.IsActive,
			IsVerified: user.IsVerified,
			IsDeleted:  user.IsDeleted,
		})
	}
	c.JSON(http.StatusOK, gin.H{"data": userResponses})
}

// func (u *UserController) Profile(c *gin.Context) {
// 	id := c.Param("id")
// 	user_id, err := strconv.Atoi(id)
// 	if err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
// 		return
// 	}
// 	user, err := crud.GetUser(user_id)
// 	if err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "User not found"})
// 		return
// 	}
// 	c.JSON(http.StatusOK, gin.H{"data": user})
// }

func (u *UserController) Profile(c *gin.Context) {
	token := c.GetHeader("Authorization")
	user, err := utils.GetCurrentUser(token)
	if err != nil {
		utils.ErrorLog.Println("Error:", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}
	userResponse := schemas.UserResponse{
		ID:         user.ID,
		Email:      user.Email,
		Username:   user.Username,
		CreatedAt:  user.CreatedAt,
		UpdatedAt:  user.UpdatedAt,
		IsActive:   user.IsActive,
		IsVerified: user.IsVerified,
		IsDeleted:  user.IsDeleted,
		Auth2FA:    user.Auth2FA,
	}
	c.JSON(http.StatusOK, gin.H{"data": userResponse})
}

func (u *UserController) Get2FADetails(c *gin.Context) {
	token := c.GetHeader("Authorization")
	currentUser, err := utils.GetCurrentUser(token)
	if err != nil {
		utils.ErrorLog.Println("Error:", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	recoverKey, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "GinTest",
		AccountName: currentUser.Username,
	})
	if err != nil {
		utils.ErrorLog.Println("Error:", "Failed to generate recovery key!", currentUser.Email)
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to generate recovery key"})
		return
	}

	secretKey, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "GinTest",
		AccountName: currentUser.Username,
	})
	if err != nil {
		utils.ErrorLog.Println("Error:", "Failed to generate secret key!", currentUser.Email)
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to generate secret key"})
		return
	}

	// Generate QR code
	secretQRCode, err := qr.Encode(secretKey.String(), qr.M, qr.Auto)
	if err != nil {
		utils.ErrorLog.Println("Error:", "Failed to generate QR code!", currentUser.Email)
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to generate QR code"})
		return
	}
	secretQRCode, _ = barcode.Scale(secretQRCode, 200, 200)

	// Convert QR code image to base64
	buffer := new(bytes.Buffer)
	if err := png.Encode(buffer, secretQRCode); err != nil {
		utils.ErrorLog.Println("Error:", "Failed to encode QR code!", currentUser.Email)
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to encode QR code"})
		return
	}
	base64Image := base64.StdEncoding.EncodeToString(buffer.Bytes())

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"base64_image": base64Image,
			"secret_key":   secretKey.Secret(),
			"recover_key":  recoverKey.Secret(),
		},
	})
}

func (u *UserController) Verify2FAOTP(c *gin.Context) {
	var authData schemas.AuthVerifyInput
	if err := c.ShouldBindJSON(&authData); err != nil {
		utils.ErrorLog.Println("Error:", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	userDb, err := crud.GetUser(authData.UserID)
	if err != nil {
		utils.ErrorLog.Println("Error:", "User not found!", userDb.Email)
		c.JSON(http.StatusNotFound, gin.H{"message": "User not found"})
		return
	}

	if authData.SecretKey == "" {
		authData.SecretKey = userDb.SecretKey
	}
	userDb.SecretKey = authData.SecretKey
	if err := crud.UpdateUser(userDb); err != nil {
		utils.ErrorLog.Println("Error:", "Error updating secret key!", userDb.Email)
		c.JSON(http.StatusBadRequest, gin.H{"message": "updating secret key"})
		return
	}

	if authData.RecoverKey != "" {
		userDb.RecoverKey = authData.RecoverKey
		if err := crud.UpdateUser(userDb); err != nil {
			utils.ErrorLog.Println("Error:", "Error updating recover key!", userDb.Email)
			c.JSON(http.StatusBadRequest, gin.H{"message": "updating recover key"})
			return
		}
	}

	if authData.OTP != "" && totp.Validate(authData.OTP, userDb.SecretKey) {
		userDb.Auth2FA = true
		if err := crud.UpdateUser(userDb); err != nil {
			utils.ErrorLog.Println("Error:", "Error updating recover key!", userDb.Email)
			c.JSON(http.StatusBadRequest, gin.H{"message": "updating recover key"})
			return
		}

		if authData.InsideFlag {
			refreshtoken, accesstoken, err := utils.GenerateToken(userDb.ID, userDb.Email)
			if err != nil {
				utils.ErrorLog.Println("Error:", "Error generating JWT token!", userDb.Email)
				c.JSON(http.StatusBadRequest, gin.H{"message": "Error generating JWT token"})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"id":          userDb.ID,
				"email":       userDb.Email,
				"is_verified": userDb.IsVerified,
				"auth_2fa":    userDb.Auth2FA,
				"token": gin.H{
					"refreshToken": refreshtoken,
					"accessToken":  accesstoken,
				},
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "OTP verified successfully"})
		return
	}
	utils.ErrorLog.Println("Error:", "Invalid verification code!", userDb.Email)
	c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid verification code"})
}

func (u *UserController) Manage2FA(c *gin.Context) {
	var authData schemas.AuthVerifyInput
	if err := c.ShouldBindJSON(&authData); err != nil {
		utils.ErrorLog.Println("Error:", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	userDb, err := crud.GetUser(authData.UserID)
	if err != nil {
		utils.ErrorLog.Println("Error:", "User not found!", userDb.Email)
		c.JSON(http.StatusNotFound, gin.H{"message": "User not found"})
		return
	}

	if authData.Enable2FA {
		userDb.SecretKey = authData.SecretKey
		userDb.RecoverKey = authData.RecoverKey
		userDb.Auth2FA = true
		if err := crud.UpdateUser(userDb); err != nil {
			utils.ErrorLog.Println("Error:", "Failed to enable 2FA!", userDb.Email)
			c.JSON(http.StatusBadRequest, gin.H{"message": "Failed to enable 2FA"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "2FA enabled successfully"})
	} else {
		userDb.SecretKey = ""
		userDb.RecoverKey = ""
		userDb.Auth2FA = false
		if err := crud.UpdateUser(userDb); err != nil {
			utils.ErrorLog.Println("Error:", "Failed to disable 2FA!", userDb.Email)
			c.JSON(http.StatusBadRequest, gin.H{"message": "Failed to disable 2FA"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "2FA disabled successfully"})
	}
}

func (u *UserController) VerifyRecoverKey(c *gin.Context) {
	var authData schemas.AuthVerifyInput
	if err := c.BindJSON(&authData); err != nil {
		utils.ErrorLog.Println("Error:", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	userDb, err := crud.GetUser(authData.UserID)
	if err != nil {
		utils.ErrorLog.Println("Error:", "User not found!", userDb.Email)
		c.JSON(http.StatusNotFound, gin.H{"message": "User not found"})
		return
	}

	if userDb.Auth2FA {
		if authData.RecoverKey != "" && userDb.RecoverKey != "" && authData.RecoverKey == userDb.RecoverKey {
			// Generate QR code
			secretKeyURI := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s", "GinTest", userDb.Username, userDb.SecretKey, "GinTest")
			secretQRCode, err := qr.Encode(secretKeyURI, qr.M, qr.Auto)
			if err != nil {
				utils.ErrorLog.Println("Error:", "Failed to generate QR code!", userDb.Email)
				c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to generate QR code"})
				return
			}
			secretQRCode, _ = barcode.Scale(secretQRCode, 200, 200)

			// Convert QR code image to base64
			buffer := new(bytes.Buffer)
			if err := png.Encode(buffer, secretQRCode); err != nil {
				utils.ErrorLog.Println("Error:", "Failed to encode QR code!", userDb.Email)
				c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to encode QR code"})
				return
			}
			base64Image := base64.StdEncoding.EncodeToString(buffer.Bytes())

			c.JSON(http.StatusOK, gin.H{
				"id":           userDb.ID,
				"base64_image": base64Image,
				"secret_key":   userDb.SecretKey,
				"message":      "Recover key verified successfully",
			})
			return
		} else {
			utils.ErrorLog.Println("Error:", "Invalid recover key!", userDb.Email)
			c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid recover key"})
			return
		}
	} else {
		utils.ErrorLog.Println("Error:", "2FA Disabled!", userDb.Email)
		c.JSON(http.StatusBadRequest, gin.H{"message": "2FA Disabled"})
	}
}

// func (u *UserController) GoogleLogin(c *gin.Context) {
//     var formData schemas.GoogleLoginInput
//     if err := c.BindJSON(&formData); err != nil {
//         c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
//         return
//     }

//     googleUserInfo, err := auth.VerifyIDToken(formData.IDToken)
//     if err != nil {
//         c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to verify ID token"})
//         return
//     }

//     firebaseID := googleUserInfo["uid"].(string)
//     email := googleUserInfo["email"].(string)
//     user, err := crud.UserExistsByEmail(email)

//     if err != nil {
//         // Handle error
//         c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
//         return
//     }

//     if user == nil {
//         fullName := googleUserInfo["first_name"].(string) + " " + googleUserInfo["last_name"].(string)
//         user = &models.User{
//             Email:     email,
//             Username:  fullName,
//             // Providers: "google",
//             // FbUID:     firebaseID,
//         }
//         if err := crud.CreateUser(user); err != nil {
//             // Handle error
//             c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
//             return
//         }
//     }

//     if user.Providers == nil {
//         c.JSON(http.StatusBadRequest, gin.H{"error": "Please login using username and password"})
//         return
//     }

//     // Assuming you have a function createAuthTokens to generate authentication tokens
//     tokens, err := createAuthTokens(user)
//     if err != nil {
//         // Handle error
//         c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate authentication tokens"})
//         return
//     }

//     // Assuming you have a function jsonifyUser to format user data
//     refreshToken, accessToken, err := utils.GenerateToken(user)

//     c.JSON(http.StatusOK, gin.H{
//         "success": true,
//         "data": gin.H{
//             "ref": refreshToken,
// 			"acc": accessToken,
//             // "user":    userData,
//         },
//         "message": "Login successful",
//     })
// }
