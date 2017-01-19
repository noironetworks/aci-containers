
BASE=github.com/noironetworks/aci-containers
METADATA_SRC=$(wildcard cnimetadata/*.go)
HOSTAGENT_SRC=$(wildcard hostagent/*.go)
AGENTCNI_SRC=$(wildcard opflexagentcni/*.go)
ACC_SRC=$(wildcard acc/*.go)

all: vendor dist/aci-containers-host-agent dist/opflex-agent-cni \
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

dist/aci-containers-host-agent: $(METADATA_SRC) $(HOSTAGENT_SRC)
	go build -v -o dist/aci-containers-host-agent $(BASE)/hostagent 

dist/aci-containers-controller: $(ACC_SRC)
	go build -v -o dist/aci-containers-controller $(BASE)/acc
