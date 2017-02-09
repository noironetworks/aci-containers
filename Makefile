
BASE=github.com/noironetworks/aci-containers
METADATA_SRC=$(wildcard metadata/*.go)
IPAM_SRC=$(wildcard ipam/*.go)
HOSTAGENT_SRC=$(wildcard hostagent/*.go)
AGENTCNI_SRC=$(wildcard opflexagentcni/*.go)
CONTROLLER_SRC=$(wildcard controller/*.go)

HOSTAGENT_DEPS=${METADATA_SRC} ${IPAM_SRC} ${HOSTAGENT_SRC}
AGENTCNI_DEPS=${METADATA_SRC} ${AGENTCNI_SRC}
CONTROLLER_DEPS=${METADATA_SRC} ${IPAM_SRC} ${CONTROLLER_SRC}

BUILD_CMD=go build -v
TEST_CMD=go test -v
INSTALL_CMD=go install -v
STATIC_BUILD_CMD=CGO_ENABLED=0 GOOS=linux ${BUILD_CMD} -a -installsuffix cgo
DOCKER_BUILD_CMD=docker build

all: vendor dist/aci-containers-host-agent dist/opflex-agent-cni \
	dist/aci-containers-controller
all-static: vendor dist-static/aci-containers-host-agent \
	dist-static/opflex-agent-cni dist/aci-containers-controller
container-all: container-host container-controller

vendor:
	glide install -strip-vendor

.PHONY: clean
clean-dist:
	rm -rf dist
clean-vendor:
	rm -rf vendor
clean: clean-dist clean-vendor

goinstall:
	${INSTALL_CMD} ${BASE}/opflexagentcni
	${INSTALL_CMD} ${BASE}/controller
	${INSTALL_CMD} ${BASE}/hostagent

dist/opflex-agent-cni: ${AGENTCNI_DEPS}
	${BUILD_CMD} -o $@ ${BASE}/opflexagentcni
dist-static/opflex-agent-cni: ${AGENTCNI_DEPS}
	${STATIC_BUILD_CMD} -o $@ ${BASE}/opflexagentcni

dist/aci-containers-host-agent: ${HOSTAGENT_DEPS}
	${BUILD_CMD} -o $@ ${BASE}/hostagent
dist-static/aci-containers-host-agent: ${HOSTAGENT_DEPS}
	${STATIC_BUILD_CMD} -o $@ ${BASE}/hostagent

dist/aci-containers-controller: ${CONTROLLER_DEPS}
	${BUILD_CMD} -o $@ ${BASE}/controller
dist-static/aci-containers-controller: ${CONTROLLER_DEPS}
	${STATIC_BUILD_CMD} -o $@ ${BASE}/controller

container-host: dist-static/aci-containers-host-agent dist-static/opflex-agent-cni
	${DOCKER_BUILD_CMD} -t noiro/aci-containers-host -f ./docker/Dockerfile-host .
container-controller: dist-static/aci-containers-controller
	${DOCKER_BUILD_CMD} -t noiro/aci-containers-controller -f ./docker/Dockerfile-controller .

check: check-ipam check-hostagent check-controller
check-ipam:
	${TEST_CMD} ${BASE}/ipam
check-hostagent:
	${TEST_CMD} ${BASE}/hostagent
check-controller:
	${TEST_CMD} ${BASE}/controller
