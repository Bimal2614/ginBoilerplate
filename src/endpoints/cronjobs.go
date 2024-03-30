package endpoints

import (
	"os"
	"strconv"

	"github.com/bimal2614/ginBoilerplate/src/controllers"
	limiter "github.com/davidleitw/gin-limiter"
	"github.com/gin-gonic/gin"
)

// SetupCronjobRouter configures the routes related to cronjob operations.
func SetupCronjobRouter(router *gin.RouterGroup, dispatcher *limiter.Dispatcher) {
	// Fetch base path for cronjob-related routes from environment or use default.
	basePath := os.Getenv("CRONJOB_BASE_PATH")
	if basePath == "" {
		basePath = "/v1" // Default base path
	}

	// Initialize the controller responsible for handling cronjob requests.
	cronjobController := controllers.NewCronjobController(
		os.Getenv("LOG_DIRECTORY"), // Fetches the log directory path from environment variables.
		30,                         // Sets the maximum age in days for log files before they are considered old and eligible for deletion.
	)
	// Create a sub-router for cronjob routes.
	cronjobRoutes := router.Group(basePath)

	// Fetch rate limit configuration for the delete-old-log-files endpoint from environment or use default.
	rateLimitPeriod := os.Getenv("CRONJOB_RATE_LIMIT_PERIOD")
	if rateLimitPeriod == "" {
		rateLimitPeriod = "1-d" // Default rate limit period
	}
	rateLimitRequestsStr := os.Getenv("CRONJOB_RATE_LIMIT_REQUESTS")
	rateLimitRequests, err := strconv.Atoi(rateLimitRequestsStr)
	if err != nil {
		rateLimitRequests = 5 // Default rate limit requests
	}

	// Register the endpoint for deleting old log files with rate limiting.
	cronjobRoutes.POST("/delete-old-log-files", dispatcher.MiddleWare(rateLimitPeriod, rateLimitRequests), cronjobController.DeleteOldLogFiles)
}
