package main

import (
	"github.com/gin-gonic/gin"
)

func SetupUserRoutes(router *gin.RouterGroup) {

	userRoutes := router.Group("/v1")
	{
		userRoutes.POST("/login", login)
		userRoutes.POST("/register", register)
		userRoutes.POST("send-otp", sendOTP)
		userRoutes.POST("verify-otp", verifyOTP)
		userRoutes.POST("forgot-password", forgotPassword)
		userRoutes.POST("reset-password", resetPassword)

		userRoutes.GET("/users", getUsers)
		userRoutes.GET("/users/:id", getUser)
	}

}
