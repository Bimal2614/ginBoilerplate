package main

import (
	"fmt"
	"time"

	"github.com/bimal2614/ginBoilerplate/database"
	"github.com/bimal2614/ginBoilerplate/src/endpoints"
	"github.com/bimal2614/ginBoilerplate/src/utils"
	limiter "github.com/davidleitw/gin-limiter"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/joho/godotenv"
)

func ResponseTimeMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Start timer
		startTime := time.Now()

		// Process request
		c.Next()

		// Calculate response time
		endTime := time.Now()
		latency := endTime.Sub(startTime)

		// log the user IP, request method, status code, and latency
		utils.ErrorLog.Printf("IP: %s - EndTime: [%v] %v %v %v\n", c.ClientIP(), endTime.Format("2006-01-02 15:04:05"), c.Request.Method, c.Request.URL.Path, latency)
		// fmt.Printf("IP: %s - EndTime: [%v] %v %v %v\n", c.ClientIP(), endTime.Format("2006-01-02 15:04:05"), c.Request.Method, c.Request.URL.Path, latency)
	}
}

func main() {

	// Load environment variables
	if err := godotenv.Load(); err != nil {
		fmt.Println("No .env file found")
	}

	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379", Password: "", DB: 0})
	dispatcher, err := limiter.LimitDispatcher("24-M", 100, rdb)

	if err != nil {
		fmt.Println(err)
	}
	// gin.SetMode(gin.ReleaseMode)

	router := gin.Default()

	// Mount routes from different endpoint groups
	router.Use(ResponseTimeMiddleware())
	api := router.Group("/api")
	{
		// Mount routes from all endpoints.go
		endpoints.SetupUserRoutes(api, dispatcher)
		endpoints.SetupWebsocketRoutes(router)
	}

	// Initialize the database connection
	err_ := database.InitDB()
	if err_ != nil {
		panic(err_)
	}
	utils.Logger()
	router.Run(":8080")
}
