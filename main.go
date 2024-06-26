package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/bimal2614/ginBoilerplate/database"
	_ "github.com/bimal2614/ginBoilerplate/docs"
	pb "github.com/bimal2614/ginBoilerplate/grpc"
	"github.com/bimal2614/ginBoilerplate/src/endpoints"
	"github.com/bimal2614/ginBoilerplate/src/schemas"
	"github.com/bimal2614/ginBoilerplate/src/utils"
	limiter "github.com/davidleitw/gin-limiter"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/joho/godotenv"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
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

// For GRPC
type server struct {
	pb.UnimplementedUserVelidateServer
}

// For GRPC responce functionality
func (s *server) UserToken(ctx context.Context, in *pb.UserTokenRequest) (*pb.UserTokenResponse, error) {
	peer, _ := peer.FromContext(ctx)
	// Extract client IP address from context
	userDb, err := utils.GetCurrentUser(in.GetToken())
	if err != nil {
		utils.ErrorLog.Println("TokenRequest:", "IP:", peer.Addr.String())
		return &pb.UserTokenResponse{UserData: err.Error(), Status: false}, nil
	}
	utils.ErrorLog.Println("TokenRequest:", "IP:", peer.Addr.String(), "Email:", userDb.Email)
	fmt.Println("user_email", userDb.Email)
	userResponse := schemas.UserGrpcResponse{
		ID:         userDb.ID,
		Email:      userDb.Email,
		Username:   userDb.Username,
		CreatedAt:  userDb.CreatedAt,
		IsVerified: userDb.IsVerified,
	}
	jsonUserData, _ := json.Marshal(userResponse)
	return &pb.UserTokenResponse{UserData: string(jsonUserData), Status: true}, nil
}

// @title           Gin Book Service
// @version         1.0
// @description     A book management service API in Go using Gin framework.

// @host      localhost:8000
// @BasePath  /api/v1

func main() {
	// Load environment variables from a .env file.
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: No .env file found. Default configurations will be used.")
	}

	utils.CreateGoogleCredFile()

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
	// router.Use(cors.Default())
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"*"},
		AllowHeaders:     []string{"Content-Type", "Content-Length", "Accept-Encoding", "Authorization", "Cache-Control"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))
	router.Static("/static", "static")

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

	// url := ginSwagger.URL("http://localhost:8000/swagger/doc.json")
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	//GRPC server connection
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterUserVelidateServer(s, &server{})
	log.Println("Server started at :50051")

	go func() {
		if err := s.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()

	serverPort := os.Getenv("SERVER_PORT")
	if serverPort == "" {
		serverPort = ":8000" // Default port
	}
	if err := router.Run(serverPort); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
