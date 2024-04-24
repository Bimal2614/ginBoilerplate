package main

import (
	"context"
	"log"
	"time"

	pb "github.com/bimal2614/ginBoilerplate/grpc"

	"google.golang.org/grpc"
)

func main() {
	// Set up a connection to the server.
	conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Fatalf("could not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewUserVelidateClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	token := "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJFbWFpbCI6ImR1bXkzMTU0QGdtYWlsLmNvbSIsIlZlcmlmaWVyIjoiZDY3MmUyNzYzNTIwMDBhODdhYzkwYWM1Mzc3NjQ3NmMiLCJleHAiOjE3MTQwMjEyOTQsInVzZXJJRCI6ImUzYjY2YWYwLTI3MjMtNDI1Ni1hMzFmLTk3ZDM5YzRhYjNjYyJ9.f7f1svOkMH4a6hnoSYt4DjikXxUkP3bMOHdvYJ8lc6E"

	// Contact the server and print out its response.
	r, err := c.UserToken(ctx, &pb.UserTokenRequest{Token: token})
	if err != nil {
		log.Fatalf("could not greet: %v", err)
	}
	log.Printf("response: %s", r.GetUserData())
}
