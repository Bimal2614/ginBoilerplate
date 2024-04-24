package main

import (
	"context"
	"fmt"
	"log"
	"net"

	pb "github.com/bimal2614/ginBoilerplate/grpc" // Import your Protocol Buffers package

	"google.golang.org/grpc"
)

type server struct {
	pb.UnimplementedUserVelidateServer
}

// func (s *server) SayHelloAgain(ctx context.Context, in *pb.HelloRequest) (*pb.HelloReply, error) {
// 	log.Printf("Received request from user: %s", in.GetName())
// 	return &pb.HelloReply{Message: "Hello again " + in.GetName()}, nil
// }

func (s *server) UserToken(ctx context.Context, in *pb.UserTokenRequest) (*pb.UserTokenResponse, error) {
	// Extract client IP address from context
	fmt.Println("$$$$$$$$$$$$$$", in.GetToken())
	// userID, err := utils.UserCheck(in.GetToken())
	// if err != nil {
	// 	return &pb.UserTokenResponse{UserData: err.Error()}, nil
	// }
	// user, err := crud.GetUser(userID)
	// if err != nil || user.IsDeleted || !user.IsVerified {
	// 	return nil, fmt.Errorf("Could not validate credentials")
	// }
	return &pb.UserTokenResponse{UserData: in.GetToken()}, nil
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterUserVelidateServer(s, &server{})
	log.Println("Server started at :50051")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
