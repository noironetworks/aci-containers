
SRCFILES=main.go

all: vendor dist/ep-mapper-daemon

vendor:
	glide install -strip-vendor

.PHONY: clean
clean:
	rm -rf dist vendor

dist/ep-mapper-daemon: $(SRCFILES)
	go build -v -o dist/ep-mapper-daemon
