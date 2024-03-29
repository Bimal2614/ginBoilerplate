package main

import (
	"fmt"

	"github.com/bimal2614/ginBoilerplate/database"
	"github.com/bimal2614/ginBoilerplate/src/endpoints"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

// call initDB function from database/init_db.go

func main() {

	// Load environment variables
	if err := godotenv.Load(); err != nil {
		fmt.Println("No .env file found")
	}

	// gin.SetMode(gin.ReleaseMode)

	router := gin.Default()

	// Mount routes from different endpoint groups
	api := router.Group("/api")
	{
		// Mount routes from all endpoints.go
		endpoints.SetupUserRoutes(api)
		endpoints.SetupWebsocketRoutes(router)
	}

	// Initialize the database connection
	err := database.InitDB()
	if err != nil {
		panic(err)
	}

	router.Run(":8080")
}
