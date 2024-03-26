package main

import (
	"github.com/gin-gonic/gin"
)

func main() {
	router := gin.Default()

	// Mount routes from different endpoint groups
	api := router.Group("/api")
	{
		// Mount routes from all endpoints.go

	}

	router.Run(":8080")
}
