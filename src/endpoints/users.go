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
	loginRateLimitRequestsStr := os.Getenv("LOGIN_RATE_LIMIT_REQUESTS")
	loginRateLimitRequests, err := strconv.Atoi(loginRateLimitRequestsStr)
	if err != nil {
		loginRateLimitRequests = 20 // Default rate limit requests for login
	}

	registerRateLimitPeriod := os.Getenv("REGISTER_RATE_LIMIT_PERIOD")
	if registerRateLimitPeriod == "" {
		registerRateLimitPeriod = "1-h" // Default rate limit period for register
	}
	registerRateLimitRequestsStr := os.Getenv("REGISTER_RATE_LIMIT_REQUESTS")
	registerRateLimitRequests, err := strconv.Atoi(registerRateLimitRequestsStr)
	if err != nil {
		registerRateLimitRequests = 20 // Default rate limit requests for register
	}

	// Setup routes with dynamic rate limiting
	userRoutes.POST("/login", dispatcher.MiddleWare(loginRateLimitPeriod, loginRateLimitRequests), userController.Login)
	userRoutes.POST("/register", dispatcher.MiddleWare(registerRateLimitPeriod, registerRateLimitRequests), userController.Register)
	userRoutes.POST("/verify-otp", userController.VerifyOTP)

	// Additional routes can be added here in a similar manner
	// userRoutes.POST("/send-otp", sendOTP)
	// userRoutes.POST("/forgot-password", forgotPassword)
	// userRoutes.POST("/reset-password", resetPassword)

	// userRoutes.GET("/users", getUsers)
	// userRoutes.GET("/users/:id", getUser)
}
