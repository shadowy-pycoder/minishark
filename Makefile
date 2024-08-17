APP_NAME?=minishark

all: build

build: 
	CGO_ENABLED=0 go build -ldflags "-s -w" -trimpath -o ./bin/${APP_NAME} ./cmd/${APP_NAME}/*.go

setcap:
	sudo setcap cap_net_raw+ep ./bin/${APP_NAME}

create:
	go test -c -race && sudo setcap cap_net_raw+ep minishark.test

bench: create
	./minishark.test -test.bench=. -test.benchmem -test.run=^$$ -test.benchtime 10000x \
	-test.cpuprofile='cpu.prof' -test.memprofile='mem.prof'
