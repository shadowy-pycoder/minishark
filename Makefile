APP_NAME=mshark

all: build

.PHONY: build
build: 
	CGO_ENABLED=0 go build -ldflags "-s -w" -trimpath -o ./bin/${APP_NAME} ./cmd/${APP_NAME}/*.go

.PHONY: setcap
setcap:
	sudo setcap cap_net_raw+ep ./bin/${APP_NAME}

.PHONY: create
create:
	go test -c -race && sudo setcap cap_net_raw+ep mshark.test

.PHONY: bench
bench: create
	./mshark.test -test.bench=. -test.benchmem -test.run=^$$ -test.benchtime 1000x \
	-test.cpuprofile='cpu.prof' -test.memprofile='mem.prof'

.PHONY: clean
clean:
	rm -v *.txt *.pcap*
