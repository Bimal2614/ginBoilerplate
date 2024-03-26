package controllers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/bimal2614/ginBoilerplate/src/models"

	"github.com/bimal2614/ginBoilerplate/src/utils/auth"

	"github.com/bimal2614/ginBoilerplate/src/crud"

	"github.com/bimal2614/ginBoilerplate/database"
)

func login(c *gin.Context) {
	// Get the JSON body and decode into variables
	var user models.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// Check if the user exists in the database
	if err := database.DB.Where("email = ? AND password = ?", user.Email, user.Password).First(&user).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Record not found!"})
		return
	}
	// Generate a JWT token
	token, err := auth.GenerateToken(user.ID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Error generating JWT token"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": token})
}

func register(c *gin.Context) {
	// Get the JSON body and decode into variables
	var user models.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// Create the user
	if err := crud.CreateUser(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Error creating user"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": user})
}

func sendOTP(c *gin.Context) {
	// Get the JSON body and decode into variables
	var user models.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// Check if the user exists in the database
	if err := database.DB.Where("email = ?", user.Email).First(&user).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Record not found!"})
		return
	}
	// Generate an OTP
	otp := auth.GenerateOTP()
	// Send the OTP to the user's email
	if err := auth.SendOTP(user.Email, otp); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Error sending OTP"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "OTP sent successfully"})
}

func verifyOTP(c *gin.Context) {
	// Get the JSON body and decode into variables
	var user models.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// Check if the user exists in the database
	if err := database.DB.Where("email = ?", user.Email).First(&user).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Record not found!"})
		return
	}
	// Verify the OTP
	if err := auth.VerifyOTP(user.Email, user.OTP); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid OTP"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "OTP verified successfully"})
}

func forgotPassword(c *gin.Context) {
	// Get the JSON body and decode into variables
	var user models.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// Check if the user exists in the database
	if err := database.DB.Where("email = ?", user.Email).First(&user).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Record not found!"})
		return
	}
	// Generate a new password
	newPassword := auth.GeneratePassword()
	// Update the user's password
	user.Password = newPassword
	if err := crud.UpdateUser(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Error updating password"})
		return
	}
	// Send the new password to the user's email
	if err := auth.SendPassword(user.Email, newPassword); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Error sending password"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Password reset successfully"})
}

func resetPassword(c *gin.Context) {
	// Get the JSON body and decode into variables
	var user models.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// Check if the user exists in the database
	if err := database.DB.Where("email = ?", user.Email).First(&user).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Record not found!"})
		return
	}
	// Update the user's password
	if err := crud.UpdateUser(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Error updating password"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Password reset successfully"})
}

func getUsers(c *gin.Context) {
	users, err := crud.GetUsers()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Error fetching users"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": users})
}

func getUser(c *gin.Context) {
	id := c.Param("id")
	user, err := crud.GetUser(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Error fetching user"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": user})
}
