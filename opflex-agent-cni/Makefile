
SRCFILES=opflex-agent-cni.go ovs.go

all: vendor dist/opflex-agent-cni

vendor:
	glide install -strip-vendor

.PHONY: clean
clean:
	rm -rf dist vendor

dist/opflex-agent-cni: $(SRCFILES)
	go build -v -o dist/opflex-agent-cni 
