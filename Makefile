
BASE=github.com/noironetworks/aci-containers
METADATA_SRC=$(wildcard cnimetadata/*.go)
EPMAPPER_SRC=$(wildcard epmapperdaemon/*.go)
AGENTCNI_SRC=$(wildcard opflexagentcni/*.go)
ACC_SRC=$(wildcard acc/*.go)

all: vendor dist/ep-mapper-daemon dist/opflex-agent-cni \
	dist/aci-containers-controller

vendor:
	glide install -strip-vendor

.PHONY: clean
clean-dist:
	rm -rf dist
clean-vendor:
	rm -rf vendor
clean: clean-dist clean-vendor

dist/opflex-agent-cni: $(METADATA_SRC) $(AGENTCNI_SRC)
	go build -v -o dist/opflex-agent-cni $(BASE)/opflexagentcni

dist/ep-mapper-daemon: $(METADATA_SRC) $(EPMAPPER_SRC)
	go build -v -o dist/ep-mapper-daemon $(BASE)/epmapperdaemon 

dist/aci-containers-controller: $(METADATA_SRC) $(ACC_SRC)
	go build -v -o dist/aci-containers-controller $(BASE)/acc
