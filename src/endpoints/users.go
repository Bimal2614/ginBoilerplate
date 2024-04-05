package endpoints

import (
	"os"
	"strconv"

	"github.com/bimal2614/ginBoilerplate/src/controllers"
	limiter "github.com/davidleitw/gin-limiter"
	"github.com/gin-gonic/gin"
)

func SetupUserRoutes(router *gin.RouterGroup, dispatcher *limiter.Dispatcher) {
	basePath := os.Getenv("USER_ROUTE_BASE_PATH")
	if basePath == "" {
		basePath = "/v1" // Default base path
	}

	userRoutes := router.Group(basePath)

	userController := controllers.NewUserController()

	// Fetch rate limit configuration from environment or use default.
	loginRateLimitPeriod := os.Getenv("LOGIN_RATE_LIMIT_PERIOD")
	if loginRateLimitPeriod == "" {
		loginRateLimitPeriod = "1-h" // Default rate limit period for login
	}
	loginRateLimitRequests, _ := strconv.Atoi(os.Getenv("LOGIN_RATE_LIMIT_REQUESTS"))
	if loginRateLimitRequests == 0 {
		loginRateLimitRequests = 20 // Default rate limit requests for login
	}

	registerRateLimitPeriod := os.Getenv("REGISTER_RATE_LIMIT_PERIOD")
	if registerRateLimitPeriod == "" {
		registerRateLimitPeriod = "1-h" // Default rate limit period for register
	}
	registerRateLimitRequests, _ := strconv.Atoi(os.Getenv("REGISTER_RATE_LIMIT_REQUESTS"))
	if registerRateLimitRequests == 0 {
		registerRateLimitRequests = 20 // Default rate limit requests for register
	}

	// Setup routes with dynamic rate limiting
	userRoutes.POST("/login", dispatcher.MiddleWare(loginRateLimitPeriod, loginRateLimitRequests), userController.Login)
	userRoutes.POST("/register", dispatcher.MiddleWare(registerRateLimitPeriod, registerRateLimitRequests), userController.Register)
	userRoutes.POST("/user-verify-otp", userController.VerifyOTP)
	userRoutes.POST("/send-otp", userController.SendOTP)
	userRoutes.POST("/forgot-password", userController.ForgotPassword)
	userRoutes.POST("/change-password", userController.ChangePassword)
	userRoutes.GET("/get-all-users", userController.GetUsers)
	userRoutes.GET("/profile", userController.Profile)
	userRoutes.GET("/get-2FA-detail", userController.Get2FADetails)
	userRoutes.POST("/verify-2FA-otp", userController.Verify2FAOTP)
	userRoutes.POST("/manage-2FA", userController.Manage2FA)
	userRoutes.POST("/verify-recover-key", userController.VerifyRecoverKey)
	userRoutes.POST("/logout", userController.LogOut)
}
