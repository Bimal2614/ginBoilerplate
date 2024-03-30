package endpoints

import (
	"github.com/bimal2614/ginBoilerplate/src/controllers"
	limiter "github.com/davidleitw/gin-limiter"
	"github.com/gin-gonic/gin"
)

func SetupUserRoutes(router *gin.RouterGroup, dispatcher *limiter.Dispatcher) {

	userRoutes := router.Group("/v1")

	userController := controllers.NewUserController()
	{
		//  add rate limiter
		userRoutes.POST("/login", dispatcher.MiddleWare("1-m", 10), userController.Login)
		userRoutes.POST("/register", dispatcher.MiddleWare("1-d", 20), userController.Register)
		userRoutes.POST("/verify-otp", userController.VerifyOTP)
	}

}

// userRoutes.POST("send-otp", sendOTP)
// userRoutes.POST("forgot-password", forgotPassword)
// userRoutes.POST("reset-password", resetPassword)

// userRoutes.GET("/users", getUsers)
// userRoutes.GET("/users/:id", getUser)
