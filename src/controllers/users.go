package controllers

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"image/png"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"time"

	firebase "firebase.google.com/go"

	"google.golang.org/api/option"

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

// Login logs in a user.
// @Summary Logs in a user
// @Description Logs in a user with the provided credentials
// @Tags users
// @Accept json
// @Produce json
// @Param user body schemas.UserLogInInput true "Login Request"
// @Success 200 {string} string "Successful login"
// @Failure 400 {string} string "failed login"
// @Router /login [post]
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

	if dbUser.Provider == "Google" {
		utils.ErrorLog.Println("Error:", "Please login with google to continue!", user.Email)
		c.JSON(http.StatusNotFound, gin.H{"message": "Please login with google to continue"})
		return
	}

	// check user verified or not
	if !dbUser.IsVerified {
		c.JSON(http.StatusOK, gin.H{
			"message": "User not verify",
			"data": gin.H{
				"id":          dbUser.ID,
				"email":       dbUser.Email,
				"is_verified": dbUser.IsVerified,
			},
		})
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

	dbUser.Verifier = utils.GenerateRandomKey(16)
	if err := crud.UpdateUser(dbUser); err != nil {
		utils.ErrorLog.Println("Error:", "Error updating recover key!", dbUser.Email)
		c.JSON(http.StatusBadRequest, gin.H{"message": "updating recover key"})
		return
	}
	// Generate a JWT token
	refreshtoken, accesstoken, err := utils.GenerateToken(dbUser.ID, dbUser.Email, dbUser.Verifier)
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

func (u *UserController) LogOut(c *gin.Context) {
	token := c.GetHeader("Authorization")
	userDb, err := utils.GetCurrentUser(token)
	if err != nil {
		utils.ErrorLog.Println("Error:", err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{"message": err.Error()})
		return
	}

	userDb.Verifier = utils.GenerateRandomKey(16)
	if err := crud.UpdateUser(userDb); err != nil {
		utils.ErrorLog.Println("Error:", "Error updating recover key!", userDb.Email)
		c.JSON(http.StatusBadRequest, gin.H{"message": "error updating verifier key"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User logged out successfully"})
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

	//generate otp
	otp := utils.GenerateOTP()

	//generate access token for mail verify
	access_token := utils.CreateEmailAccessToken(user.Email)

	link := os.Getenv("CLIENT_URL") + "/verify-mail?" +
		"token=" + access_token +
		"&key=" + strconv.Itoa(int(otp)) +
		"&type=user-verify"

	// Send the OTP to the user's email
	if err := utils.SendOTP(user.Email, link); err != nil {
		utils.ErrorLog.Println("Error:", "Error sending OTP!", user.Email)
		c.JSON(http.StatusBadRequest, gin.H{"message": "Error sending OTP"})
		return
	}

	// save the otp in the database
	emailOtp := models.EmailOtp{
		Email:  user.Email,
		OTP:    uint(otp),
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
	c.JSON(http.StatusOK, gin.H{"data": userSchema, "message": "Verify link sent to your email, please verify your email to continue"})
}

func (u *UserController) SendOTP(c *gin.Context) {
	// Get the JSON body and decode into variables
	var user schemas.ReSendOTPInput
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	// normalize the email
	user.Email = utils.NormalizeEmail(user.Email)

	// Check if the user exists in the database
	userDb, err := crud.UserExistsByEmail(user.Email)
	if err != nil {
		utils.ErrorLog.Println("Error:", "User not found!", user.Email)
		c.JSON(http.StatusNotFound, gin.H{"message": "User not found!"})
		return
	}

	// Generate an OTP
	otp := utils.GenerateOTP()

	//generate access token for mail verify
	access_token := utils.CreateEmailAccessToken(user.Email)

	//generate link for otp verify
	var link string
	if userDb.IsVerified {
		link = os.Getenv("CLIENT_URL") + "/forget-password/change-password?" +
			"token=" + access_token +
			"&key=" + strconv.Itoa(int(otp)) +
			"&type=reset-password"
	} else {
		link = os.Getenv("CLIENT_URL") + "/verify-mail?" +
			"token=" + access_token +
			"&key=" + strconv.Itoa(int(otp)) +
			"&type=user-verify"
	}
	// Send the OTP to the user's email
	if err := utils.SendOTP(user.Email, link); err != nil {
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
		OTP:    uint(otp),
		UserID: userDb.ID,
	}

	if err := crud.CreateEmailOtp(&newEmailOtp); err != nil {
		utils.ErrorLog.Println("Error:", "Error creating OTP!", user.Email)
		c.JSON(http.StatusBadRequest, gin.H{"message": "Error creating OTP"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Link sent your email successfully"})
}

func (u *UserController) VerifyOTP(c *gin.Context) {
	// Get the JSON body and decode into variables
	var request_data schemas.VerifyOTPInput
	if err := c.ShouldBindJSON(&request_data); err != nil {
		utils.ErrorLog.Println("Error:", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	email, err := utils.DecodeEmailAccessToken(request_data.EmailToken)
	if err != nil {
		utils.ErrorLog.Println("Error:", err.Error())
		c.JSON(http.StatusNotFound, gin.H{"message": err.Error()})
		return
	}

	// Check if the user exists in the database
	userDb, err := crud.UserExistsByEmail(email)
	if err != nil {
		utils.ErrorLog.Println("Error:", "Record not found!", email)
		c.JSON(http.StatusNotFound, gin.H{"message": "Record not found!"})
		return
	}

	//  check if the user is already verified
	if userDb.IsVerified {
		utils.ErrorLog.Println("Error:", "User already verified!", userDb.Email)
		c.JSON(http.StatusBadRequest, gin.H{"message": "User already verified!"})
		return
	}

	//  check is otp exists
	emailOtp, _ := crud.OtpExistsByEmail(email)
	if emailOtp != nil {
		//check is otp right or wrong
		if emailOtp.OTP != request_data.OTP {
			utils.ErrorLog.Println("Error:", "OTP mismatched, Please provide correct OTP!", userDb.Email)
			c.JSON(http.StatusBadRequest, gin.H{"message": "OTP mismatched, Please provide correct OTP"})
			return
		}
		validityPeriod := 10 * time.Minute
		currentTime := time.Now()
		//check otp time
		if !emailOtp.CreatedAt.Add(validityPeriod).Before(currentTime) {
			// Update the user's password
			userDb.IsVerified = true
			if err := crud.UpdateUser(userDb); err != nil {
				utils.ErrorLog.Println("Error:", "Error updating password!", userDb.Email)
				c.JSON(http.StatusBadRequest, gin.H{"message": "Error updating password"})
				return
			}

			// Delete the OTP from the database
			if err := crud.DeleteEmailOtp(emailOtp); err != nil {
				utils.ErrorLog.Println("Error:", "Error deleting OTP!", userDb.Email)
				c.JSON(http.StatusBadRequest, gin.H{"message": "Error deleting OTP"})
				return
			}
		} else {
			// OTP has expired
			utils.ErrorLog.Println("Error:", "OTP has expired!", userDb.Email)
			c.JSON(http.StatusBadRequest, gin.H{"message": "OTP has expired!"})
			return
		}
	} else {
		// User OTP not add in database
		utils.ErrorLog.Println("Error:", "OTP not found!", userDb.Email)
		c.JSON(http.StatusNotFound, gin.H{"message": "OTP not found!"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User verified successfully"})
}

func (u *UserController) ForgotPassword(c *gin.Context) {
	// Get the JSON body and decode into variables
	var user schemas.ForgotPasswordInput
	if err := c.ShouldBindJSON(&user); err != nil {
		utils.ErrorLog.Println("Error:", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	//decode email tekon
	email, err := utils.DecodeEmailAccessToken(user.EmailToken)
	if err != nil {
		utils.ErrorLog.Println("Error:", err.Error())
		c.JSON(http.StatusNotFound, gin.H{"message": err.Error()})
		return
	}

	//  check is user exists
	userDb, err := crud.UserExistsByEmail(email)
	if err != nil {
		utils.ErrorLog.Println("Error:", "User not found!", email)
		c.JSON(http.StatusNotFound, gin.H{"message": "User not found!"})
		return
	}

	//  check is otp exists
	emailOtp, _ := crud.OtpExistsByEmail(email)
	if emailOtp != nil {
		//check is otp right or wrong
		if emailOtp.OTP != user.OTP {
			utils.ErrorLog.Println("Error:", "OTP mismatched, Please provide correct OTP!", email)
			c.JSON(http.StatusBadRequest, gin.H{"message": "OTP mismatched, Please provide correct OTP"})
			return
		}
		validityPeriod := 10 * time.Minute
		currentTime := time.Now()
		//check otp time
		if !emailOtp.CreatedAt.Add(validityPeriod).Before(currentTime) {
			// check for the length of the password and email structure
			if len(user.NewPassword) < 6 {
				utils.ErrorLog.Println("Error:", "Password must be at least 6 characters long!", email)
				c.JSON(http.StatusBadRequest, gin.H{"message": "Password must be at least 6 characters long"})
				return
			}
			// Generate a new password
			passwordHash, err := utils.EncryptPassword(user.NewPassword)
			if err != nil {
				utils.ErrorLog.Println("Error:", "Error encrypting password!", email)
				c.JSON(http.StatusBadRequest, gin.H{"message": "Error encrypting password"})
				return
			}
			// Update the user's password
			userDb.Password = passwordHash
			if err := crud.UpdateUser(userDb); err != nil {
				utils.ErrorLog.Println("Error:", "Error updating password!", email)
				c.JSON(http.StatusBadRequest, gin.H{"message": "Error updating password"})
				return
			}

			// Delete the OTP from the database
			if err := crud.DeleteEmailOtp(emailOtp); err != nil {
				utils.ErrorLog.Println("Error:", "Error deleting OTP!", email)
				c.JSON(http.StatusBadRequest, gin.H{"message": "Error deleting OTP"})
				return
			}
		} else {
			// OTP has expired
			utils.ErrorLog.Println("Error:", "OTP has expired!", email)
			c.JSON(http.StatusBadRequest, gin.H{"message": "OTP has expired!"})
			return
		}
	} else {
		// User OTP not add in database
		utils.ErrorLog.Println("Error:", "OTP not found!", email)
		c.JSON(http.StatusNotFound, gin.H{"message": "OTP not found!"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password reset successfully"})
}

func (u *UserController) ChangePassword(c *gin.Context) {
	token := c.GetHeader("Authorization")
	dbUser, err := utils.GetCurrentUser(token)
	if err != nil {
		utils.ErrorLog.Println("Error:", err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{"message": err.Error()})
		return
	}
	//Get the JSON body and decode into variables
	var user schemas.ChangePasswordInput
	if err := c.ShouldBindJSON(&user); err != nil {
		utils.ErrorLog.Println("Error:", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	//check old password in db
	comp := utils.ComparePasswords(dbUser.Password, user.OldPassword)
	if !comp {
		utils.ErrorLog.Println("Error:", "Old password is incorrect!", dbUser.Email)
		c.JSON(http.StatusBadRequest, gin.H{"message": "Old password is incorrect"})
		return
	}

	//ckeck add user old password and new password
	if user.OldPassword == user.NewPassword {
		utils.ErrorLog.Println("Error:", "Old password and new password are the same!", dbUser.Email)
		c.JSON(http.StatusBadRequest, gin.H{"message": "Old password and new password are the same!"})
		return
	}

	// check for the length of the password
	if len(user.NewPassword) < 6 {
		utils.ErrorLog.Println("Error:", "Password must be at least 6 characters long!", dbUser.Email)
		c.JSON(http.StatusBadRequest, gin.H{"message": "Password must be at least 6 characters long"})
		return
	}

	// encrypt the new password
	passwordHash, err := utils.EncryptPassword(user.NewPassword)
	if err != nil {
		utils.ErrorLog.Println("Error:", "encrypting password!", dbUser.Email)
		c.JSON(http.StatusBadRequest, gin.H{"message": "Error encrypting password"})
		return
	}
	// Update the user's password
	dbUser.Password = passwordHash
	if err := crud.UpdateUser(dbUser); err != nil {
		utils.ErrorLog.Println("Error:", "updating password!", dbUser.Email)
		c.JSON(http.StatusBadRequest, gin.H{"message": "Error updating password"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Password change successfully"})
}

func (u *UserController) GetUsers(c *gin.Context) {
	// Parse query parameters for pagination
	page, err := strconv.Atoi(c.DefaultQuery("page", "1"))
	if err != nil || page < 1 {
		page = 1
	}

	limit, err := strconv.Atoi(c.DefaultQuery("limit", "10"))
	if err != nil || limit < 1 {
		limit = 10
	}

	// Calculate offset
	offset := (page - 1) * limit

	users, count, err := crud.GetUsers(offset, limit)
	if err != nil {
		utils.ErrorLog.Println("Error:", "Error fetching users!")
		c.JSON(http.StatusBadRequest, gin.H{"message": "Error fetching users"})
		return
	}

	var userResponses []schemas.UserResponse
	for _, user := range *users {
		if user.Image == "" {
			user.Image = ""
		} else {
			user.Image = os.Getenv("PLATFORM_URL") + "/" + user.Image
		}
		userResponses = append(userResponses, schemas.UserResponse{
			ID:         user.ID,
			Email:      user.Email,
			Username:   user.Username,
			Image:      user.Image,
			CreatedAt:  user.CreatedAt,
			UpdatedAt:  user.UpdatedAt,
			IsActive:   user.IsActive,
			IsVerified: user.IsVerified,
			IsDeleted:  user.IsDeleted,
		})
	}
	c.JSON(http.StatusOK, gin.H{"data": userResponses, "count": count})
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
		c.JSON(http.StatusUnauthorized, gin.H{"message": err.Error()})
		return
	}
	var pro_url string
	if user.Image == "" {
		pro_url = ""
	} else {
		pro_url = os.Getenv("PLATFORM_URL") + "/" + user.Image
	}
	// pro_url := os.Getenv("PLATFORM_URL") + "/" + user.Image
	userResponse := schemas.UserResponse{
		ID:         user.ID,
		Email:      user.Email,
		Username:   user.Username,
		Image:      pro_url,
		CreatedAt:  user.CreatedAt,
		UpdatedAt:  user.UpdatedAt,
		IsActive:   user.IsActive,
		IsVerified: user.IsVerified,
		IsDeleted:  user.IsDeleted,
		Auth2FA:    user.Auth2FA,
	}
	c.JSON(http.StatusOK, gin.H{"data": userResponse})
}

func (u *UserController) UpdateProfile(c *gin.Context) {
	token := c.GetHeader("Authorization")
	userDb, err := utils.GetCurrentUser(token)
	if err != nil {
		utils.ErrorLog.Println("Error:", err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{"message": err.Error()})
		return
	}

	profile, _ := c.FormFile("pro_dp")
	if profile != nil {
		// Update the user profile image
		filepath := utils.SaveStaticFile(c, profile, userDb.ID)
		if filepath == "" {
			utils.ErrorLog.Println("Error:", "Profile image not getting!", userDb.Email)
			c.JSON(http.StatusBadRequest, gin.H{"message": "Error profile image not getting"})
			return
		}

		if userDb.Image != "" {
			os.Remove(userDb.Image)
		}
		userDb.Image = filepath
	}
	username := c.PostForm("username")
	if username != "" {
		// check user name unique or not
		if err := crud.CheckUserName(username); err == nil {
			errorMessage := fmt.Sprintf("%s username not available!", username)
			utils.ErrorLog.Println("Error:", errorMessage, userDb.Email)
			c.JSON(http.StatusBadRequest, gin.H{"message": errorMessage})
			return
		}
		userDb.Username = username
	}

	if err := crud.UpdateUser(userDb); err != nil {
		utils.ErrorLog.Println("Error:", "Error updating profile!", userDb.Email)
		c.JSON(http.StatusBadRequest, gin.H{"message": "Error updating profile"})
		return
	}

	var pro_url string
	if userDb.Image == "" {
		pro_url = ""
	} else {
		pro_url = os.Getenv("PLATFORM_URL") + "/" + userDb.Image
	}
	userResponse := schemas.UserResponse{
		ID:         userDb.ID,
		Email:      userDb.Email,
		Username:   userDb.Username,
		Image:      pro_url,
		CreatedAt:  userDb.CreatedAt,
		UpdatedAt:  userDb.UpdatedAt,
		IsActive:   userDb.IsActive,
		IsVerified: userDb.IsVerified,
		IsDeleted:  userDb.IsDeleted,
		Auth2FA:    userDb.Auth2FA,
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
			userDb.Verifier = utils.GenerateRandomKey(16)
			if err := crud.UpdateUser(userDb); err != nil {
				utils.ErrorLog.Println("Error:", "Error updating recover key!", userDb.Email)
				c.JSON(http.StatusBadRequest, gin.H{"message": "Error updating verifier key"})
				return
			}

			refreshtoken, accesstoken, err := utils.GenerateToken(userDb.ID, userDb.Email, userDb.Verifier)
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

func (u *UserController) GoogleLogin(c *gin.Context) {
	var formData schemas.GoogleLoginInput
	if err := c.BindJSON(&formData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
		return
	}

	opt := option.WithCredentialsFile("google_service.json")
	app, err := firebase.NewApp(context.Background(), nil, opt)
	if err != nil {
		utils.ErrorLog.Println("Error:", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}

	client, err := app.Auth(context.Background())
	if err != nil {
		utils.ErrorLog.Println("Error:", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}

	// Verify Google ID token
	token, err := client.VerifyIDToken(context.Background(), formData.IDToken)
	if err != nil {
		utils.ErrorLog.Println("Error:", "Failed to verify google ID token")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to verify ID token"})
		return
	}

	// Extract user information from the verified token
	email := token.Claims["email"].(string)
	user, _ := crud.UserExistsByEmail(email)
	verifier := utils.GenerateRandomKey(16)

	// If the user does not exist, create a new user
	if user == nil {
		user = &models.User{
			Email:      email,
			Username:   email,
			Provider:   "Google",
			IsVerified: true,
			Verifier:   verifier,
		}
		if err := crud.CreateUser(user); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
			return
		}
	} else if user.Provider != "Google" {
		utils.ErrorLog.Println("Error:", "Please login using email and password", email)
		c.JSON(http.StatusBadRequest, gin.H{"message": "Please login using email and password"})
		return
	} else {
		if user.Auth2FA {
			c.JSON(http.StatusOK, gin.H{
				"message": "Please otp verify",
				"data": gin.H{
					"id":          user.ID,
					"email":       user.Email,
					"is_verified": user.IsVerified,
					"auth_2fa":    user.Auth2FA,
				},
			})
			return
		}
	}

	//Generate authentication tokens
	refreshtoken, accesstoken, err := utils.GenerateToken(user.ID, user.Email, user.Verifier)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate authentication tokens"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"id":          user.ID,
		"email":       user.Email,
		"is_verified": user.IsVerified,
		"auth_2fa":    user.Auth2FA,
		"token": gin.H{
			"refreshToken": refreshtoken,
			"accessToken":  accesstoken,
		},
	})
}
