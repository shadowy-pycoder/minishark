APP_NAME?=minishark

build: 
	CGO_ENABLED=0 go build -ldflags "-s -w" -trimpath -o ./bin/${APP_NAME} ./cmd/${APP_NAME}/*.go

setcap:
	sudo setcap cap_net_raw+ep ./bin/${APP_NAME}
