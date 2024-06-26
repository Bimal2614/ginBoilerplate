# This is a boilerplate for the go language gin framework

### Task

- [ ] Auth
- [ ] Pagination
- [ ] Limiter
- [ ] Cors
- [ ] CSRF
- [ ] SSo
- [ ] 2 FA
- [ ] Websocket
- [ ] Reddis
- [ ] Celery

# Installation step

## Step 1 Clone the repositoty
```
git clone https://github.com/Bimal2614/ginBoilerplate
cd ginBoilerplate/
```

## Step 2 For golang
```
sudo snap install go --classic
sudo apt install golang-go
go version
sudo apt update
```

## Step 3 For swagger create(optional)
- run swag init command for update swagger

## Step 4 For redis
```
sudo apt install redis-server
sudo apt update
sudo systemctl start redis-server
redis-server
```

## Step 5 Create .env file and added creds
```
sudo nano .env
```

## Step 6 Start server
```
pm2 start app.yaml
```

# Step 7 Restart server
```
cd
git pull
pm2 restart all
```


# For GRPC
- sudo snap install protobuf --classic
- sudo apt install protobuf-compiler
- go get -u github.com/golang/protobuf/{proto,protoc-gen-go}
- Run nano ~/.bash_profile
- Add export GO_PATH=~/go      export PATH=$PATH:/$GO_PATH/bin
- Run source ~/.bash_profile
- Run protoc --go_out=. --go_opt=paths=source_relative grpc/grpc.proto  ---> generate Go code for Protocol Buffers messages. It's typically used for defining message types and serialization/deserialization methods.
- Run protoc --go-grpc_out=. --go-grpc_opt=paths=source_relative grpc/grpc.proto   ----> generate Go code specifically for gRPC services. It generates service interfaces and server/client stubs that enable communication between gRPC clients and servers.

