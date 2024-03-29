package endpoints

import (
	"github.com/bimal2614/ginBoilerplate/src/controllers"
	"github.com/gin-gonic/gin"
)

func SetupUserRoutes(router *gin.RouterGroup) {

	userRoutes := router.Group("/v1")

	userController := controllers.NewUserController()
	{
		userRoutes.POST("/login", userController.Login)
		userRoutes.POST("/register", userController.Register)
		userRoutes.POST("/verify-otp", userController.VerifyOTP)
	}

}

// userRoutes.POST("send-otp", sendOTP)
// userRoutes.POST("forgot-password", forgotPassword)
// userRoutes.POST("reset-password", resetPassword)

// userRoutes.GET("/users", getUsers)
// userRoutes.GET("/users/:id", getUser)
