package main

import (
	"log"
	"os"
	"strconv"
	"time"

	"github.com/bimal2614/ginBoilerplate/database"
	"github.com/bimal2614/ginBoilerplate/src/endpoints"
	"github.com/bimal2614/ginBoilerplate/src/utils"
	limiter "github.com/davidleitw/gin-limiter"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/joho/godotenv"
)

// ResponseTimeMiddleware logs the time taken to respond to a request.
// It captures the start time before a request is processed and the end time after processing,
// then logs the latency along with the client IP, request method, and request path.
func ResponseTimeMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		startTime := time.Now()
		c.Next()
		latency := time.Since(startTime)
		utils.ErrorLog.Printf("IP: %s - EndTime: [%v] %v %v %v\n", c.ClientIP(), time.Now().Format(time.RFC3339), c.Request.Method, c.Request.URL.Path, latency)
	}
}

func main() {
	// Load environment variables from a .env file.
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: No .env file found. Default configurations will be used.")
	}

	// Initialize Redis client with environment variables or default values.
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}
	redisPassword := os.Getenv("REDIS_PASSWORD")
	redisDB, err := strconv.Atoi(os.Getenv("REDIS_DB"))
	if err != nil {
		log.Fatalf("Failed to convert REDIS_DB to integer: %v", err)
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: redisPassword,
		DB:       redisDB,
	})

	// Setup request rate limiter using Redis.
	rateLimit := os.Getenv("RATE_LIMIT")
	if rateLimit == "" {
		rateLimit = "1-M" // Default rate limit
	}
	// requestsPerMinute, err := strconv.Atoi(os.Getenv("REQUESTS_PER_MINUTE"))
	requestsPerMinute, _ := strconv.Atoi(os.Getenv("REQUESTS_PER_MINUTE"))
	if requestsPerMinute == 0 {
		requestsPerMinute = 10
	}

	dispatcher, err := limiter.LimitDispatcher(rateLimit, requestsPerMinute, rdb)
	if err != nil {
		log.Fatalf("Failed to setup rate limiter: %v", err)
	}

	router := gin.Default()
	router.Use(ResponseTimeMiddleware())
	router.Use(cors.Default())

	api := router.Group("/api")
	{
		endpoints.SetupUserRoutes(api, dispatcher)
		endpoints.SetupCronjobRouter(api, dispatcher)
		endpoints.SetupWebsocketRoutes(router)
	}

	if err := database.InitDB(); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	// database.Migrate()

	utils.Logger()

	serverPort := os.Getenv("SERVER_PORT")
	if serverPort == "" {
		serverPort = ":8080" // Default port
	}
	if err := router.Run(serverPort); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
